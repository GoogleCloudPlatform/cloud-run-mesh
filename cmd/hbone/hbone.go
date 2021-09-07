//Copyright 2021 Google LLC
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/costinm/cloud-run-mesh/pkg/gcp"
	"github.com/costinm/cloud-run-mesh/pkg/gcp/meshca"
	"github.com/costinm/cloud-run-mesh/pkg/hbone"
	"github.com/costinm/cloud-run-mesh/pkg/istioca"
	"github.com/costinm/cloud-run-mesh/pkg/mesh"
	sts2 "github.com/costinm/cloud-run-mesh/pkg/sts"
)

var (
	//localForwards arrayFlags
	localForward  = flag.String("L", "", "Local port, if set connections to this port will be forwarded to the mesh service")
	remoteForward = flag.String("R", "", "Remote forward")


	//mesh  = flag.String("mesh", "", "Mesh Environment - URL or path to mesh environment spec. If empty, mesh will be autodetected")
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return strings.Join(*i, ",")
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

// Create a HBONE tunnel.
//
// Will attempt to discover an east-west gateway and get credentials using KUBE_CONFIG or google credentials.
//
// For example:
//
// ssh -o ProxyCommand='hbone %h:22' root@fortio-cr.fortio
//
// If the server doesn't have persistent SSH key, add to the ssh parameters:
//      -F /dev/null -o StrictHostKeyChecking=no -o "UserKnownHostsFile /dev/null"
//
func main() {
	// WIP - multiple ports
	//flag.Var(&localForwards, "LocalForward", "SSH-style local forward")
	flag.Parse()

	kr := mesh.New("")

	kr.VendorInit = gcp.InitGCP

	ctx, cf := context.WithTimeout(context.Background(), 10000 * time.Second)
	defer cf()

	// Use kubeconfig or gcp to find the cluster
	err := kr.LoadConfig(ctx)
	if err != nil {
		log.Fatal("Failed to connect to K8S ", time.Since(kr.StartTime), kr, os.Environ(), err)
	}

	// Not calling RefreshAndSaveFiles - hbone is not creating files, jwts and certs in memory only.
	// Also not initializing pilot-agent or envoy - this is just using k8s to configure the hbone tunnel

	auth := hbone.NewAuth()
	priv, csr, err := auth.NewCSR("rsa", kr.TrustDomain,"spiffe://" + kr.TrustDomain + "/ns/" + kr.Namespace + "/sa/" + kr.KSA)
	if err != nil {
		log.Fatal("Failed to find mesh certificates ", err)
	}
	// Trust MeshCA and in-cluster Citadel
	auth.AddRoots([]byte(gcp.MeshCA))

	tokenProvider, err := sts2.NewSTS(kr)

	if kr.MeshConnectorAddr == "" {
		log.Fatal("Failed to find in-cluster, missing 'hgate' service in mesh env")
	}

	kr.XDSAddr = kr.MeshConnectorAddr+ ":15012"

	// TODO: move to library, possibly to separate CLI (authtool ?)
	// Hbone 'base' should just use the mesh cert files, call tool or expect cron to renew
	if kr.CitadelRoot != "" && kr.MeshConnectorAddr != "" {
		auth.AddRoots([]byte(kr.CitadelRoot))

		cca, err := istioca.NewCitadelClient(&istioca.Options{
			TokenProvider: &mesh.IstiodCredentialsProvider{KRun: kr},
			CAEndpoint: kr.MeshConnectorAddr + ":15012",
			TrustedRoots: auth.TrustedCertPool,
			CAEndpointSAN: "istiod.istio-system.svc",
		})
		if err != nil {
			log.Fatal(err)
		}
		chain, err := cca.CSRSign(csr, 24*3600)

		//log.Println(chain, err)
		err = auth.SetKeysPEM(priv, chain)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		// TODO: Use MeshCA if citadel is not in cluster

		mca, err := meshca.NewGoogleCAClient("", tokenProvider)
		chain, err := mca.CSRSign(csr, 24*3600)

		if err != nil {
			log.Fatal(err)
		}
		//log.Println(chain, priv)
		err = auth.SetKeysPEM(priv, chain)
		if err != nil {
			log.Fatal(err)
		}
	}

	hb := hbone.New(auth)

	if *localForward != "" {
		go localForwardPort(hb, kr.MeshConnectorAddr, auth)
	}
	if *remoteForward != "" {
		go remoteForwardPort(*remoteForward, hb, kr.MeshConnectorAddr, kr, auth)
	}

	if len(flag.Args()) == 0 && *localForward == "" && *remoteForward == "" {
		flag.Usage()
		os.Exit(1)
	}

	if len(flag.Args()) > 0 {
		dest := flag.Arg(0)
		err := forward(dest, hb, kr.MeshConnectorAddr, auth, os.Stdin, os.Stdout)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		select {}
	}
}

func forward(dest string, hb *hbone.HBone, hg string, auth *hbone.Auth,  in io.Reader, out io.WriteCloser) error {
	host := ""
	if strings.Contains(dest, "//") {
		u, _ := url.Parse(dest)

		host, _, _ = net.SplitHostPort(u.Host)
	} else {
		host, _, _ = net.SplitHostPort(dest)
	}
	// TODO: k8s discovery for hgate
	// TODO: -R to register to the gate, reverse proxy
	// TODO: get certs

	hc := hb.NewEndpoint(dest)

	if strings.HasSuffix(host, ".svc") {
		hc.H2Gate = hg + ":15008" // hbone/mtls
		hc.ExternalMTLSConfig = auth.MeshTLSConfig
	}
	// Initialization done - starting the proxy either on a listener or stdin.

	err := hc.Proxy(context.Background(),in, out)
	if err != nil {
		return err
	}
	return nil
}

func remoteForwardPort(rf string, hb *hbone.HBone, hg string, kr *mesh.KRun, auth *hbone.Auth) {
	parts := strings.SplitN(rf, ":", 3)
	if len(parts) != 3 {
		log.Fatal("Expecting 3 parts", rf)
	}

	attachC := hb.NewClient( kr.Name+ "." + kr.Namespace + ":15009")
	attachE := attachC.NewEndpoint("")
	attachE.SNI = fmt.Sprintf("outbound_.8080_._.%s.%s.svc.cluster.local", kr.Name, kr.Namespace)
	go func() {
		_, err := attachE.DialH2R(context.Background(), hg+":15441")
		log.Println("H2R connected", hg, err)
	}()
}

func localForwardPort(hb *hbone.HBone, hg string, auth *hbone.Auth) {
	parts := strings.SplitN(*localForward, ":", 2)
	if len(parts) != 2 {
		log.Fatal("Expecting 2 parts", *localForward)
	}
	dest := parts[1]

	l, err := net.Listen("tcp", "127.0.0.1:"+parts[0])
	if err != nil {
		panic(err)
	}

	for {
		a, err := l.Accept()
		if err != nil {
			panic(err)
		}
		go func() {
			forward(dest, hb, hg, auth, a, a)
		}()
	}
}
