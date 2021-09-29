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
	"log"
	"os"
	"time"

	"github.com/costinm/cloud-run-mesh/pkg/gcp"
	"github.com/costinm/cloud-run-mesh/pkg/hbone"
	"github.com/costinm/cloud-run-mesh/pkg/mesh"
)

var initDebug func(run *mesh.KRun)

func main() {
	kr := mesh.New("")

	kr.VendorInit = gcp.InitGCP

	err := kr.LoadConfig(context.Background())
	if err != nil {
		log.Fatal("Failed to connect to mesh ", time.Since(kr.StartTime), kr, os.Environ(), err)
	}

	log.Println("K8S Client initialized", kr.ProjectId, kr.ClusterLocation, kr.ClusterName, kr.ProjectNumber,
		kr.KSA, kr.Namespace, kr.Name, kr.Labels, kr.XDSAddr)

	kr.RefreshAndSaveFiles()

	meshMode := true

	if _, err := os.Stat("/usr/local/bin/pilot-agent"); os.IsNotExist(err) {
		meshMode = false
	}
	if kr.XDSAddr == "-" {
		meshMode = false
	}

	if meshMode {
		// Use k8s client to autoconfigure, reading from cluster.
		err := kr.StartIstioAgent()
		if err != nil {
			log.Fatal("Failed to start the mesh agent ", err)
		}
		err = kr.WaitReady(10 * time.Second)
		if err != nil {
			log.Fatal("Mesh agent not ready ", err)
		}
	}

	kr.StartApp()

	// TODO: wait for app  ready before binding to port - using same CloudRun 'bind to port 8080' or proper health check

	// Start internal SSH server, for debug and port forwarding. Can be conditionally compiled.
	if initDebug != nil {
		// Split for conditional compilation (to compile without ssh dep)
		go initDebug(kr)
	}

	// Start the tunnel: accepts H2 streams, decrypt the stream as mTLS, forward plain text to 15003 (envoy) which
	// applies the metrics/enforcements and forwards to the app on 8080
	// The certs are currently created by agent - WIP to create them from launcher, so proxyless gRPC doesn't require pilot-agent.
	auth, err := hbone.NewAuthFromDir("")
	if err != nil {
		log.Fatal("Failed to find mesh certificates ", err)
	}
	// Support MeshCA (required for MCP). Citadel will be supported if it is used in the mesh.
	auth.AddRoots([]byte(gcp.MeshCA))

	// 15009 is the reserved port for HBONE using H2C. CloudRun or other gateways using H2C will forward to this
	// port.
	hb := hbone.New(auth)
	// This is a port on envoy, created by Sidecar or directly by Istiod.
	// Needs to be plain-text HTTP
	hb.TcpAddr = "127.0.0.1:15003" // must match sni-service-template port in Sidecar
	_, err = hbone.ListenAndServeTCP(":15009", hb.HandleAcceptedH2C)
	if err != nil {
		log.Fatal("Failed to start h2c on 15009", err)
	}

	// Experimental: if hgate east-west gateway present, create a connection.
	if os.Getenv("H2R") != "" {
		hg := kr.MeshConnectorInternalAddr
		if hg == "" {
			hg = kr.MeshConnectorAddr
		}
		if hg == "" {
			log.Println("hgate not found, not attaching to the cluster", err)
		} else {
			attachC := hb.NewClient(kr.Name + "." + kr.Namespace + ":15009")
			attachE := attachC.NewEndpoint("")
			attachE.SNI = fmt.Sprintf("outbound_.8080_._.%s.%s.svc.cluster.local", kr.Name, kr.Namespace)
			go func() {
				_, err := attachE.DialH2R(context.Background(), hg+":15441")
				log.Println("H2R connected", hg, err)
			}()
		}
	}

	select {}
}
