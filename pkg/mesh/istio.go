// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mesh

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/creack/pty"
)

// Istio injected environment:
//
// - env variables - we load them form 'mesh-env' plus internal
//
// - volumes:
//  /var/run/secrets/istio - istiod-ca-cert   - confingMap:istio-ca-root-cert
//  /var/lib/istio/data    - istio-data      - empty dir ???
//  /etc/istio/proxy       - istio-envoy     - memory, RW
//  /var/run/secrets/tokens - istio-token     - audience=trustDomain
//  /etc/istio/pod          - istio-podinfo   - labels, annotations
//  /var/run/secrets/kubernetes.io/serviceaccount - xx-token-yy (by kubelet/service account controller)
//

// MeshConfig is a minimal mesh config - used to load in-cluster settings used in injection.
type MeshConfig struct {
	TrustDomain   string      `yaml:"trustDomain,omitempty"`
	DefaultConfig ProxyConfig `yaml:"defaultConfig,omitempty"`
}

type ProxyConfig struct {
	DiscoveryAddress  string            `yaml:"discoveryAddress,omitempty"`
	MeshId            string            `yaml:"meshId,omitempty"`
	ProxyMetadata     map[string]string `yaml:"proxyMetadata,omitempty"`
	CaCertificatesPem []string          `yaml:"caCertificatesPem,omitempty"`
}

// Setup /etc/resolv.conf when running as root, with pilot-agent resolving DNS
//
// When running as root:
// - if /var/lib/istio/resolv.conf is found, use it.
// - else, copy /etc/resolv.conf to /var/lib/istio/resolv.conf and create a new resolv.conf
func resolvConfForRoot() {
	if _, err := os.Stat("/var/lib/istio/resolv.conf"); !os.IsNotExist(err) {
		log.Println("Alternate resolv.conf exists")
		return
	}

	os.MkdirAll("/var/lib/istio", 0755)
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		log.Println("Failed to read resolv.conf, DNS interception will fail ", err)
		return
	}
	err = os.WriteFile("/var/lib/istio/resolv.conf", data, 0755)
	if err != nil {
		log.Println("Failed to create alternate resolv.conf, DNS interception will fail ", err)
		return
	}
	err = os.WriteFile("/etc/resolv.conf", []byte(`nameserver: 127.0.0.1`), 755)
	if err != nil {
		log.Println("Failed to create resolv.conf, DNS interception will fail ", err)
		return
	}
	log.Println("Adjusted resolv.conf")
}

func (kr *KRun) agentCommand() *exec.Cmd {
	// From the template:

	//- proxy
	//- sidecar
	//- --domain
	//- $(POD_NAMESPACE).svc.{{ .Values.global.proxy.clusterDomain }}
	//- --proxyLogLevel={{ annotation .ObjectMeta `sidecar.istio.io/logLevel` .Values.global.proxy.logLevel }}
	//- --proxyComponentLogLevel={{ annotation .ObjectMeta `sidecar.istio.io/componentLogLevel` .Values.global.proxy.componentLogLevel }}
	//- --log_output_level={{ annotation .ObjectMeta `sidecar.istio.io/agentLogLevel` .Values.global.logging.level }}
	//{{- if .Values.global.sts.servicePort }}
	//- --stsPort={{ .Values.global.sts.servicePort }}
	//{{- end }}
	//{{- if .Values.global.logAsJson }}
	//- --log_as_json
	//{{- end }}
	//{{- if gt .EstimatedConcurrency 0 }}
	//- --concurrency
	//- "{{ .EstimatedConcurrency }}"
	//{{- end -}}
	//{{- if .Values.global.proxy.lifecycle }}
	args := []string{"proxy"}
	if kr.Gateway != "" {
		args = append(args, "router")
	} else {
		args = append(args, "sidecar")
	}
	args = append(args, "--domain")
	args = append(args, kr.Namespace+".svc.cluster.local")
	args = append(args, "--serviceCluster")
	args = append(args, kr.Name+"."+kr.Namespace)

	if kr.AgentDebug != "" {
		args = append(args, "--log_output_level="+kr.AgentDebug)
	}
	args = append(args, "--stsPort=15463")
	return exec.Command("/usr/local/bin/pilot-agent", args...)
}


// StartIstioAgent creates the env and starts istio agent.
// If running as root, will also init iptables and change UID to 1337.
func (kr *KRun) StartIstioAgent() error {
	if kr.XDSAddr == "-" {
		return nil
	}

	prefix := "."
	if os.Getuid() == 0 {
		prefix = ""
	}
	os.MkdirAll(prefix+"/etc/istio/proxy", 0755)

	// Save the istio certificates - for proxyless or app use.
	os.MkdirAll(prefix+"/var/run/secrets/istio", 0755)
	os.MkdirAll(prefix+"/var/run/secrets/mesh", 0755)
	os.MkdirAll(prefix+"/var/run/secrets/istio.io", 0755)
	os.MkdirAll(prefix+"/etc/istio/pod", 0755)
	if os.Getuid() == 0 {
		os.Chown(prefix+"/var/run/secrets/istio.io", 1337, 1337)
		os.Chown(prefix+"/var/run/secrets/istio", 1337, 1337)
		os.Chown(prefix+"/var/run/secrets/mesh", 1337, 1337)
		os.Chown(prefix+"/etc/istio/pod", 1337, 1337)
		os.Chown(prefix+"/etc/istio/proxy", 1337, 1337)
	}

	if kr.CitadelRoot != "" {
		ioutil.WriteFile(prefix+"/var/run/secrets/istio/root-cert.pem", []byte(kr.CitadelRoot), 0755)
	}

	// /dev/stdout is rejected - it is a pipe.
	// https://github.com/envoyproxy/envoy/issues/8297#issuecomment-620659781

	if kr.Name == "" && kr.Gateway != "" {
		kr.Name = kr.Gateway
	}

	env := os.Environ()
	// XDS and CA servers are using system certificates ( recommended ).
	// If using a private CA - add it's root to the docker images, everything will be consistent
	// and simpler !
	if os.Getenv("PROXY_CONFIG") == "" {
		if kr.MeshTenant == "-" {
			// Explicitly in-cluster
			kr.XDSAddr = kr.MeshConnectorAddr + ":15012"
		}

		proxyConfig := fmt.Sprintf(`{"discoveryAddress": "%s"}`, kr.XDSAddr)
		env = append(env, "PROXY_CONFIG="+proxyConfig)
	}

	if strings.HasSuffix(kr.XDSAddr, ":15012") {
		env = addIfMissing(env, "ISTIOD_SAN", "istiod.istio-system.svc")
	} else {
		env = addIfMissing(env,"XDS_ROOT_CA", "SYSTEM")
		env = addIfMissing(env, "PILOT_CERT_PROVIDER", "system")
		env = addIfMissing(env,"CA_ROOT_CA", "SYSTEM")
	}
	env = addIfMissing(env,"POD_NAMESPACE", kr.Namespace)
	// TODO: Pod name should be the unique name, need to add some elements from
	// K_REVISION (ex: fortio-cr-00011-duq) and metadata.
	env = addIfMissing(env,"POD_NAME", kr.Name)

	kr.initLabelsFile()

	env = addIfMissing(env, "OUTPUT_CERTS", prefix+"/var/run/secrets/istio.io/")

	// This would be used if a audience-less JWT was present - not possible with TokenRequest
	// TODO: add support for passing a long lived 1p JWT in a file, for local run
	//env = append(env, "JWT_POLICY=first-party-jwt")

	kr.WhiteboxMode = os.Getenv("ISTIO_META_INTERCEPTION_MODE") == "NONE"
	if os.Getuid() != 0 {
		kr.WhiteboxMode = true
	}
	if kr.Gateway != "" {
		kr.WhiteboxMode = true
	}

	if !kr.WhiteboxMode { //&& kr.Gateway != "" {
		err := kr.runIptablesSetup(env)
		if err != nil {
			log.Println("iptables disabled ", err)
			kr.WhiteboxMode = true
		} else {
			log.Println("iptables interception enabled")
		}
	} else {
		log.Println("No iptables - starting with INTERCEPTION_MODE=NONE")
	}

	// Currently broken in iptables - use whitebox interception, but still run it
	if !kr.WhiteboxMode {
		resolvConfForRoot()
		env = addIfMissing(env, "ISTIO_META_DNS_CAPTURE", "true")
		env = addIfMissing(env, "DNS_PROXY_ADDR", "localhost:53")
	}

	// MCP config
	// The following 2 are required for MeshCA.
	env = addIfMissing(env, "GKE_CLUSTER_URL" ,fmt.Sprintf("https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s",
		kr.ProjectId, kr.ClusterLocation, kr.ClusterName))
	env = addIfMissing(env, "GCP_METADATA", fmt.Sprintf("%s|%s|%s|%s",
		kr.ProjectId, kr.ProjectNumber, kr.ClusterName, kr.ClusterLocation))

	env = addIfMissing(env, "XDS_ADDR", kr.XDSAddr)
	//env = append(env, "CA_ROOT_CA=/etc/ssl/certs/ca-certificates.crt")
	//env = append(env, "XDS_ROOT_CA=/etc/ssl/certs/ca-certificates.crt")

	env = addIfMissing(env, "JWT_POLICY", "third-party-jwt")


	env = addIfMissing(env, "TRUST_DOMAIN", kr.TrustDomain)

	// If MCP is available, and PROXY_CONFIG is not set explicitly
	if kr.MeshTenant != "" && kr.MeshTenant != "-" && os.Getenv("PROXY_CONFIG") == "" {
		env = addIfMissing(env, "CA_ADDR", "meshca.googleapis.com:443")
		env = addIfMissing(env, "XDS_AUTH_PROVIDER", "gcp")

		env = addIfMissing(env, "ISTIO_META_CLOUDRUN_ADDR", kr.MeshTenant)

		// Will be used to set a clusterid metadata, which will locate the remote cluster id
		// This is used for multi-cluster, to specify the k8s client to use for validating tokens in Istiod
		env = addIfMissing(env, "ISTIO_META_CLUSTER_ID", fmt.Sprintf("cn-%s-%s-%s",
			kr.ProjectId, kr.ClusterLocation, kr.ClusterName))
	}

	if kr.WhiteboxMode {
		env = append(env, "ISTIO_META_INTERCEPTION_MODE=NONE")
		env = append(env, "HTTP_PROXY_PORT=15007")
	}

	// WIP: automate getting the CR addr (or have Thetis handle it)
	// For example by reading a configmap in cluster
	//--set-env-vars="ISTIO_META_CLOUDRUN_ADDR=asm-stg-asm-cr-asm-managed-rapid-c-2o26nc3aha-uc.a.run.app:443" \

	// If set, let istiod generate bootstrap
	// TODO: remove, probably not needed.
	bootstrapIstiod := os.Getenv("BOOTSTRAP_XDS_AGENT")
	if bootstrapIstiod == "" {
		if _, err := os.Stat(prefix + "/var/lib/istio/envoy/hbone_tmpl.json"); os.IsNotExist(err) {
			os.MkdirAll(prefix+"/var/lib/istio/envoy/", 0755)
			err = ioutil.WriteFile(prefix+"/var/lib/istio/envoy/envoy_bootstrap_tmpl.json",
				[]byte(EnvoyBootstrapTmpl), 0755)
			if err != nil {
				panic(err)
			}
		} else {
			custom, err := ioutil.ReadFile(prefix + "/var/lib/istio/envoy/hbone_tmpl.json")
			if err != nil {
				panic(err) // no point continuing
			}
			err = ioutil.WriteFile(prefix+"/var/lib/istio/envoy/envoy_bootstrap_tmpl.json",
				[]byte(custom), 0755)
			if err != nil {
				panic(err)
			}
		}
	}

	// Environment detection: if the docker image or VM does not include an Envoy use the 'grpc agent' mode,
	// i.e. only get certificate.
	if _, err := os.Stat("/usr/local/bin/envoy"); os.IsNotExist(err) {
		env = append(env, "DISABLE_ENVOY=true")
	}

	// Generate grpc bootstrap - no harm, low cost
	if os.Getenv("GRPC_XDS_BOOTSTRAP") == "" {
		env = append(env, "GRPC_XDS_BOOTSTRAP=./var/run/grpc_bootstrap.json")
	}
	cmd := kr.agentCommand()
	var stdout io.ReadCloser
	if os.Getuid() == 0 {
		os.MkdirAll("/etc/istio/proxy", 777)
		os.Chown("/etc/istio/proxy", 1337, 1337)

		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.SysProcAttr.Credential = &syscall.Credential{
			Uid: 0,
			Gid: 1337,
		}
		pty, tty, err := pty.Open()
		if err != nil {
			log.Println("Error opening pty ", err)
			stdout, _ = cmd.StdoutPipe()
			os.Stdout.Chown(1337, 1337)
		} else {
			cmd.Stdout = tty
			err = tty.Chown(1337, 1337)
			if err != nil {
				log.Println("Error chown ", tty.Name(), err)
			} else {
				log.Println("Opened pyy", tty.Name(), pty.Name())
			}
			stdout = pty
		}
		cmd.Dir = "/"
	} else {
		cmd.Stdout = os.Stdout
		env = append(env, "ISTIO_META_UNPRIVILEGED_POD=true")
	}
	cmd.Env = env

	cmd.Stderr = os.Stderr
	os.MkdirAll(prefix+"/var/lib/istio/envoy/", 0700)

	go func() {
		log.Println("Starting mesh agent ", env)
		err := cmd.Start()
		if err != nil {
			log.Println("Failed to start ", cmd, err)
		}
		kr.agentCmd = cmd
		if stdout != nil {
			go func() {
				io.Copy(os.Stdout, stdout)
			}()
		}
		err = cmd.Wait()
		if err != nil {
			log.Println("Wait err ", err)
		}
		kr.Exit(0)
	}()

	// TODO: wait for agent to be ready
	return nil
}

func addIfMissing(env []string, key, val string) []string {
	if os.Getenv(key) != "" {
		return env
	}

	return append(env, key + "=" + val)
}

func (kr *KRun) Exit(code int) {
	if kr.agentCmd != nil && kr.agentCmd.Process != nil {
		kr.agentCmd.Process.Kill()
	}
	if kr.appCmd != nil && kr.appCmd.Process != nil {
		kr.appCmd.Process.Kill()
	}
	os.Exit(code)
}

func (kr *KRun) initLabelsFile() {
	labels := ""
	if kr.Gateway != "" {
		labels = fmt.Sprintf(
			`version="v1"
security.istio.io/tlsMode="istio"
istio="%s"
`, kr.Gateway)
	} else {
		labels = fmt.Sprintf(
			`version="v1"
security.istio.io/tlsMode="istio"
app="%s"
service.istio.io/canonical-name="%s"
`, kr.Name, kr.Name)
	}
	os.MkdirAll("./etc/istio/pod",755)
	err := ioutil.WriteFile("./etc/istio/pod/labels", []byte(labels), 0777)
	if err == nil {
		log.Println("Written labels: ", labels)
	} else {
		log.Println("Error writing labels", err)
	}
}

func (kr *KRun) runIptablesSetup(env []string) error {
	// TODO: make the args the default !
	// pilot-agent istio-iptables -p 15001 -u 1337 -m REDIRECT -i '*' -b "" -x "" -- crash

	//pilot-agent istio-iptables -p 15001 -u 1337 -m REDIRECT -i '10.8.4.0/24' -b "" -x ""
	cmd := exec.Command("/usr/local/bin/pilot-agent",
		"istio-iptables",
		"-p", "15001", // outbound capture port
		//"-z", "15006", - no inbound interception
		"-u", "1337",
		"-m", "REDIRECT",
		"-i", "10.0.0.0/8", // all outbound captured
		"-b", "", // disable all inbound redirection
		// "-d", "15090,15021,15020", // exclude specific ports
		"-x", "")
	cmd.Env = env
	cmd.Dir = "/"
	so := &bytes.Buffer{}
	se := &bytes.Buffer{}
	cmd.Stdout = so
	cmd.Stderr = se
	err := cmd.Start()
	if err != nil {
		log.Println("Error starting iptables", err, so.String(), "stderr:", se.String())
		return err
	} else {
		err = cmd.Wait()
		if err != nil {
			log.Println("Error starting iptables", err, so.String(), "stderr:", se.String())
			return err
		}
	}
	// TODO: make the stdout/stderr available in a debug endpoint
	return nil
}

// TODO: lookup istiod service and endpoints ( instead of using an ILB or external name)
//
