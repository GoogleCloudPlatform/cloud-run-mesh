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

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/gcp"
	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/hbone"
	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/mesh"
	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/sts"
)

var initDebug func(run *mesh.KRun)

func main() {
	ctx := context.Background()
	kr := mesh.New()

	// If InitForTDFromMeshEnv returns true, then we will use TD mesh
	if kr.InitForTDFromMeshEnv() {
		startTd(kr)
		select {}
	}
	err := gcp.InitGCP(ctx, kr)
	if err != nil {
		log.Fatal("Failed to find K8S ", time.Since(kr.StartTime), kr, os.Environ(), err)
	}

	// Use env and vendor init to discover the mesh - including APIserver, XDS, roots.
	err = kr.LoadConfig(context.Background())
	if err != nil {
		log.Fatal("Failed to connect to mesh ", time.Since(kr.StartTime), kr, os.Environ(), err)
	}

	meshMode := true

	if _, err := os.Stat("/usr/local/bin/pilot-agent"); os.IsNotExist(err) {
		meshMode = false
	}
	if kr.XDSAddr == "-" {
		meshMode = false
	}

	if meshMode {
		log.Println("K8S Client initialized", "cluster", kr.ClusterAddress,
			"project_number", kr.ProjectNumber, "instanceID", kr.InstanceID,
			"ksa", kr.KSA, "ns", kr.Namespace,
			"name", kr.Name,
			"labels", kr.Labels, "XDS", kr.XDSAddr, "initTime", time.Since(kr.StartTime))
		// Use k8s client to autoconfigure, reading from cluster.
		kr.EnvoyStartTime = time.Now()
		err := kr.StartIstioAgent()
		if err != nil {
			log.Fatal("Failed to start the mesh agent ", err)
		}
		err = kr.WaitHTTPReady("http://127.0.0.1:15021/healthz/ready", 10*time.Second)
		if err != nil {
			cd, err := http.Get("http://127.0.0.1:15000/config_dump")
			if err == nil {
				cdb, err := ioutil.ReadAll(cd.Body)
				if err == nil {
					//os.Stderr.Write(cdb)
					ioutil.WriteFile("./var/lib/istio/envoy/config_dump.json", cdb, 0777)
				}
			}
			log.Fatal("Mesh agent not ready ", err)
		}
		kr.EnvoyReadyTime = time.Now()
	} else {
		log.Println("Proxyless init", "cluster", kr.ClusterAddress,
			"project_number", kr.ProjectNumber, "instanceID", kr.InstanceID,
			"ksa", kr.KSA, "ns", kr.Namespace,
			"name", kr.Name,
			"labels", kr.Labels, "XDS", kr.XDSAddr, "initTime", time.Since(kr.StartTime))
	}

	// TODO: wait for app  ready before binding to port - using same CloudRun 'bind to port 8080' or proper health check

	// Start internal SSH server, for debug and port forwarding. Can be conditionally compiled.
	if initDebug != nil {
		// Split for conditional compilation (to compile without ssh dep)
		go initDebug(kr)
	}

	kr.StartApp()

	err = kr.WaitAppStartup()
	if err != nil {
		log.Fatal("Timeout waiting for app", err)
	}
	log.Println("App ready",
		"app_start", kr.AppReadyTime.Sub(kr.EnvoyReadyTime),
		"envoy_time", kr.EnvoyReadyTime.Sub(kr.EnvoyStartTime),
		"init_time", kr.EnvoyStartTime.Sub(kr.StartTime))

	// Start the tunnel: accepts H2 streams, forward to 15003 (envoy) which handle mTLS
	// and applies the metrics/enforcements and forwards to the app on 8080
	//
	// 15009 is the reserved port for HBONE using H2C. This is the port that CloudRun port is set, and accepts H2 plaintext
	// connections from the CR proxy/FE (TLS is handled by the FE).
	//
	// This must start listenting LAST, after Envoy is 'ready' and the app itself is listening - otherwise requests will
	// be forwarded when the app or envoy are not ready, resulting in errors during startup.
	//
	// The H2 requests carry tunneled mTLS data to port 15003.
	//
	// Envoy listens on 15003 and terminates mTLS.
	// The port is created by the Sidecar config.
	//
	// The flow is:
	// 1. K8S Service on port 8080 ( will be changed to 80 )
	// 2. targetPort: 15443, endpoint = mesh connector
	// 3. Mesh connector decodes the SNI header, encapsulates the mTLS stream and adds the JWT
	// 4. Requests is sent to public CR address, port 443, as HTTP/2 over TLS, with the request
	// body encapsulating the mTLS stream
	// 5. CloudRun infra handles TLS and JWT authentication, forwards to port 15009
	// 6. The agent handles HTTP/2 connection, forwards the encapsulated stream to envoy on 15003
	// 7. Envoy treats the request as any mTLS connection - and eventually forwards to the application
	// port 8080.
	//
	// We use multiple ports instead of iptables magic to allow this to work in gVisor or
	// docker containers without NET_ADMIN/iptables ( including local testing/dev)
	//
	// This code path will change as Envoy support for adding JWT is added and Istio 'hbone'
	// is fully implemented.
	hb := hbone.New()
	initPorts(kr, hb)

	hbone.Debug = kr.Config("MESH_DEBUG", "") != ""
	mesh.Debug = kr.Config("MESH_DEBUG", "") != ""
	sts.Debug = kr.Config("MESH_DEBUG", "") != ""

	_, err = hbone.ListenAndServeTCP(":15009", hb.HandleAcceptedH2C)
	if err != nil {
		log.Fatal("Failed to start h2c on 15009", err)
	}

	select {}
}

func initPorts(kr *mesh.KRun, hb *hbone.HBone) {
	for k, v := range kr.MeshEnv {
		if strings.HasPrefix(k, "PORT_") && len(k) > 5 {
			hb.Ports[k[5:]] = v
		}
	}
}

func startTd(kr *mesh.KRun) {
	kr.InitForTD()
	log.Printf("Preparing to connect to TD mesh with project number: %s and scope : %s", kr.ProjectNumber, kr.TdSidecarEnv.Scope)

	if os.Getuid() != 0 {
		log.Fatal("td only supports running as root")
	}

	log.Println("Starting iptables")
	if err := kr.StartIPTablesInterception(); err != nil {
		log.Fatal("Iptables interception failed: ", err)
	}
	log.Println("Finished iptables")

	// Now we run TD start up script for IP tables interception and envoy startup.
	if err := kr.StartEnvoy(); err != nil {
		log.Fatal("Failed to start envoy ", err)
	}

	adminConsoleAddr := fmt.Sprintf("127.0.0.1:%s", kr.TdSidecarEnv.EnvoyAdminPort)
	if err := kr.WaitEnvoyReady(adminConsoleAddr, 10*time.Second); err != nil {
		log.Fatal("Failed to wait for envoy to start: ", err)
	}

	kr.StartApp()
}
