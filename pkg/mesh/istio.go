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
	"strconv"
	"strings"
	"syscall"
	"time"

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
	err = os.WriteFile("/etc/resolv.conf", []byte(`nameserver: 127.0.0.1\nsearch: google.internal.`), 755)
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
	if os.Getenv("ENVOY_LOG_LEVEL") != "" {
		args = append(args, "--proxyLogLevel="+os.Getenv("ENVOY_LOG_LEVEL"))
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
	//os.MkdirAll(prefix+"/var/lib/istio/envoy", 0755)

	// Save the istio certificates - for proxyless or app use.
	os.MkdirAll(prefix+"/var/run/secrets/istio", 0755)
	os.MkdirAll(prefix+"/var/run/secrets/mesh", 0755)
	os.MkdirAll(prefix+"/var/run/secrets/istio.io", 0755)
	os.MkdirAll(prefix+"/etc/istio/pod", 0755)
	if os.Getuid() == 0 {
		//os.Chown(prefix+"/var/lib/istio/envoy", 1337, 1337)
		os.Chown(prefix+"/var/run/secrets/istio.io", 1337, 1337)
		os.Chown(prefix+"/var/run/secrets/istio", 1337, 1337)
		os.Chown(prefix+"/var/run/secrets/mesh", 1337, 1337)
		os.Chown(prefix+"/etc/istio/pod", 1337, 1337)
		os.Chown(prefix+"/etc/istio/proxy", 1337, 1337)
	}

	// Pilot agent expects this file, containing citadel roots. Will be used to connect to the XDS server, and as
	// default root CA.
	if kr.CitadelRoot != "" {
		err := ioutil.WriteFile(prefix+"/var/run/secrets/istio/root-cert.pem", []byte(kr.CitadelRoot), 0755)
		if err != nil {
			log.Println("Failed to write citadel root", "rootCAFile", prefix + "/var/run/secrets/istio/root-cert.pem", "error", err)
		}
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
	proxyConfigEnv := os.Getenv("PROXY_CONFIG")
	if proxyConfigEnv == "" {
		addr := kr.FindXDSAddr()
		kr.XDSAddr = addr
		log.Println("XDSAddr discovery", addr, "XDS_ADDR", kr.XDSAddr, "MESH_TENANT", kr.MeshTenant)

		proxyConfig := fmt.Sprintf(`{"discoveryAddress": "%s"}`, addr)
		env = append(env, "PROXY_CONFIG="+proxyConfig)
	} else {
		log.Println("Using injected PROXY_CONFIG", proxyConfigEnv)
	}

	// Pilot-agent requires this file, to connect to CA and XDS.
	// The plan is to add code to get the certs to this package, so proxyless doesn't depend on pilot-agent.
	//
	// OSS Istio uses 'istio-ca' as token audience when connecting to Citadel
	// ASM uses the 'trust domain' - which is also needed for MCP and Stackdriver.
	// Recent Istiod supports customization of the expected audiences, via an env variable.
	//
	if strings.HasSuffix(kr.XDSAddr, ":15012") {
		env = addIfMissing(env, "ISTIOD_SAN", "istiod.istio-system.svc")
		// Temp workaround to handle OSS-specific behavior. By default we will expect OSS Istio
		// to be installed in 'compatibility' mode with ASM, i.e. accept both istio-ca and trust domain
		// as audience.
		// TODO: use the trust domain from mesh-env
		if os.Getenv("OSS_ISTIO") != "" {
			log.Println("Using istio-ca audience")
			kr.Aud2File["istio-ca"] = kr.BaseDir + "/var/run/secrets/tokens/istio-token"
		} else {
			log.Println("Using audience", kr.TrustDomain)
			kr.Aud2File[kr.TrustDomain] = kr.BaseDir + "/var/run/secrets/tokens/istio-token"
		}
	} else {
		log.Println("Using system certifates for XDS and CA")
		kr.Aud2File[kr.TrustDomain] = kr.BaseDir + "/var/run/secrets/tokens/istio-token"
		env = addIfMissing(env, "XDS_ROOT_CA", "SYSTEM")
		env = addIfMissing(env, "PILOT_CERT_PROVIDER", "system")
		env = addIfMissing(env, "CA_ROOT_CA", "SYSTEM")
	}
	env = addIfMissing(env, "POD_NAMESPACE", kr.Namespace)

	kr.RefreshAndSaveTokens()


	// Pod name MUST be an unique name - it is used in stackdriver which requires this ( errors on 'ordered updates' and
	//  lost data otherwise)
	// This also shows up in 'istioctl ps' and in istio logs

	// K_REVISION (ex: fortio-cr-00011-duq) and metadata.
	podName := os.Getenv("K_REVISION")
	hn := os.Getenv("HOSTNAME")
	if hn == "" {
		hn, _ = os.Hostname()
		hnp := strings.Split(hn, ".")
		if len(hnp) > 0 {
			hn = hnp[0]
		}
	}
	if podName != "" {
		if kr.InstanceID == "" {
			podName = podName + "-" + strconv.Itoa(time.Now().Second())
		} else if len(kr.InstanceID) > 8 {
			podName = podName + "-" + kr.InstanceID[0:8]
		} else {
			podName = podName + "-" + kr.InstanceID
		}

		if kr.Rev == "" {
			kr.Rev = podName
		}
	} else if hn != "" {
		podName = os.Getenv("HOSTNAME")
	} else {
		podName = kr.Name + "-" + "-" + strconv.Itoa(time.Now().Second())
		log.Println("Setting POD_NAME from name, missing instance ", podName)
	}
	// Some default value.
	if kr.Rev == "" {
		kr.Rev = "v1"
	}

	// If running in k8s, this is set to an unique ID
	env = addIfMissing(env, "POD_NAME", podName)
	env = addIfMissing(env, "ISTIO_META_WORKLOAD_NAME", kr.Name)

	env = addIfMissing(env, "SERVICE_ACCOUNT", kr.KSA)

	if kr.ProjectNumber != "" {
		env = addIfMissing(env, "ISTIO_META_MESH_ID", "proj-"+kr.ProjectNumber)
	}
	env = addIfMissing(env, "CANONICAL_SERVICE", kr.Name)
	env = addIfMissing(env, "CANONICAL_REVISION", kr.Rev)
	kr.initLabelsFile()

	env = addIfMissing(env, "OUTPUT_CERTS", prefix+"/var/run/secrets/istio.io/")

	// This would be used if a audience-less JWT was present - not possible with TokenRequest
	// TODO: add support for passing a long lived 1p JWT in a file, for local run
	//env = append(env, "JWT_POLICY=first-party-jwt")

	kr.WhiteboxMode = kr.Config("ISTIO_META_INTERCEPTION_MODE", "") == "NONE"
	if os.Getuid() != 0 {
		kr.WhiteboxMode = true
	}
	if kr.Gateway != "" {
		kr.WhiteboxMode = true
	}

	iptablesEnv := []string{}
	iptablesEnv = append(iptablesEnv, env...)

	if !kr.WhiteboxMode {
		err := kr.runIptablesSetup(iptablesEnv)
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
	env = addIfMissing(env, "GKE_CLUSTER_URL", kr.ClusterAddress)
	env = addIfMissing(env, "GCP_METADATA", fmt.Sprintf("%s|%s|%s|%s",
		kr.ProjectId, kr.ProjectNumber, kr.ClusterName, kr.ClusterLocation))

	env = addIfMissing(env, "XDS_ADDR", kr.XDSAddr)
	//env = append(env, "CA_ROOT_CA=/etc/ssl/certs/ca-certificates.crt")
	//env = append(env, "XDS_ROOT_CA=/etc/ssl/certs/ca-certificates.crt")

	env = addIfMissing(env, "JWT_POLICY", "third-party-jwt")

	// Fetch ProxyConfig over XDS, merge the extra root certificates
	env = addIfMissing(env, "PROXY_CONFIG_XDS_AGENT", "true")

	env = addIfMissing(env, "TRUST_DOMAIN", kr.TrustDomain)

	// Gets translated to "APP_CONTAINERS" metadata, used to identify the container.
	env = addIfMissing(env, "ISTIO_META_APP_CONTAINERS", "cloudrun")

	if kr.X509KeyPair != nil {
		// Loaded from workload cert file - no need to use citadel or mesh CA.
		env = addIfMissing(env, "CA_PROVIDER", "GoogleGkeWorkloadCertificate")
	}
	// If MCP is available, and PROXY_CONFIG is not set explicitly
	if kr.MeshTenant != "" &&
		kr.MeshTenant != "-" &&
		os.Getenv("PROXY_CONFIG") == "" {
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

	// Environment detection: if the docker image or VM does not include an Envoy use the 'grpc agent' mode,
	// i.e. only get certificate.
	if _, err := os.Stat("/usr/local/bin/envoy"); os.IsNotExist(err) {
		env = append(env, "DISABLE_ENVOY=true")
	}
	// TODO: look in /var...
	if _, err := os.Stat(" ./var/lib/istio/envoy/envoy_bootstrap_tmpl.json"); os.IsNotExist(err) {
		if _, err := os.Stat("/var/lib/istio/envoy/envoy_bootstrap_tmpl.json"); os.IsNotExist(err) {
			env = append(env, "DISABLE_ENVOY=true")
		} else {
			env = append(env, "ISTIO_BOOTSTRAP=/var/lib/istio/envoy/envoy_bootstrap_tmpl.json")
		}
	}

	// Generate grpc bootstrap - no harm, low cost.
	// TODO: New version of Istio does this automatically, will be removed
	if os.Getenv("GRPC_XDS_BOOTSTRAP") == "" {
		env = append(env, "GRPC_XDS_BOOTSTRAP=./etc/istio/proxy/grpc_bootstrap.json")
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

	//saveLaunchInfo(cmd)

	go func() {
		if Debug {
			log.Println("Starting cmd", cmd.Args)
		}
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
			if cmd.ProcessState.ExitCode() == 255 {
				log.Println("Wait err ", err, cmd.Env)
			} else {
				log.Println("Wait err ", err)
			}
			kr.Exit(1)
		}
		kr.Exit(0)
	}()

	return nil
}

// For troubleshooting, generate a file with the env and command.
// This can also be used for running krun as a periodic job instead of as a launcher
// Compile with  -gcflags  "all=-N -l"
func saveLaunchInfo(cmd *exec.Cmd) {
	b := bytes.Buffer{}
	for _, e := range cmd.Env {
		kv := strings.SplitN(e, "=", 2)
		if len(kv) == 2 {
			b.Write([]byte("export " + kv[0] + "=" + "'" + kv[1] + "'\n"))
		}
	}
	b.Write([]byte{'\n'})
	b.Write([]byte("dlv --listen=127.0.0.1:44997 --headless=true --api-version=2 --check-go-version=false --only-same-user=false exec "))
	b.Write([]byte(cmd.Args[0]))
	b.Write([]byte(" -- "))
	for _, e := range cmd.Args[1:] {
		b.Write([]byte(e))
		b.Write([]byte{' '})
	}
	b.Write([]byte{'\n'})
	ioutil.WriteFile("./var/lib/istio/envoy/cmd.sh", b.Bytes(), 0700)
}

func addIfMissing(env []string, key, val string) []string {
	if os.Getenv(key) != "" {
		return env
	}

	return append(env, key+"="+val)
}

func (kr *KRun) Exit(code int) {
	if kr.agentCmd != nil && kr.agentCmd.Process != nil {
		kr.agentCmd.Process.Signal(syscall.SIGTERM)
	}
	if kr.appCmd != nil && kr.appCmd.Process != nil {
		kr.agentCmd.Process.Signal(syscall.SIGTERM)
	}
	for _, a := range kr.Children {
		a.Process.Signal(syscall.SIGTERM)
	}
	time.Sleep(5 * time.Second)
	if kr.agentCmd != nil && kr.agentCmd.Process != nil {
		kr.agentCmd.Process.Kill()
	}
	if kr.appCmd != nil && kr.appCmd.Process != nil {
		kr.appCmd.Process.Kill()
	}
	for _, a := range kr.Children {
		a.Process.Kill()
	}
	os.Exit(code)
}

func (kr *KRun) initLabelsFile() {
	labels := ""
	if kr.Gateway != "" {
		labels = fmt.Sprintf(
			`version="%s"
security.istio.io/tlsMode="istio"
istio="%s"
`, kr.Rev, kr.Gateway)
	} else {
		labels = fmt.Sprintf(
			`version="%s"
security.istio.io/tlsMode="istio"
app="%s"
service.istio.io/canonical-name="%s"
environment="cloud-run-mesh"
`, kr.Rev, kr.Name, kr.Name)
	}
	os.MkdirAll("./etc/istio/pod", 755)
	err := ioutil.WriteFile("./etc/istio/pod/labels", []byte(labels), 0777)
	if err != nil {
		log.Println("Error writing labels", err)
	}
}

func (kr *KRun) runIptablesSetup(env []string) error {
	/*
	Injected default:
	  - -p
	    - "15001"
	    - -z
	    - "15006"
	    - -u
	    - "1337"
	    - -m
	    - REDIRECT
	    - -i
	    - '*'
	    - -x
	    - ""
	    - -b
	    - '*'
	    - -d
	    - 15090,15021,15020

	*/
	outRange := kr.Config("OUTBOUND_IP_RANGES_INCLUDE", "10.0.0.0/8")
	// Exclude ports from Envoy capture - hbone-h2, hbone-h2c
	excludePorts := kr.Config("OUTBOUND_PORTS_EXCLUDE", "15008,15009")
	if excludePorts != "15008,15009" {
		excludePorts = excludePorts + ",15008,15009"
	}

	cmd := exec.Command("/usr/local/bin/pilot-agent",
		"istio-iptables",
		// "-p", "15001", // outbound capture port, default value
		//"-z", "15006", - no inbound interception, default value
		"-u", "1337", // REQUIRED - code default is 128
		//"-m", "REDIRECT", // default value
		//"-i", "*", // OUTBOUND_IP_RANGES_INCLUDE
		"-i", outRange, // Alternative - only mesh traffic
		// "-b", "", // disable all inbound redirection, default
		// "-d", "15090,15021,15020", // exclude specific ports from inbound capture, if -b '*'
		"-o", excludePorts,
		//"-x", "", // exclude CIDR, default
	)
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
