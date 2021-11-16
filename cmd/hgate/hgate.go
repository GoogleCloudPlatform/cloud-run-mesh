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
	"log"
	"os"
	"time"

	"github.com/GoogleCloudPlatform/cloud-run-mesh/meshcon/meshconnectord"
	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/gcp"
	_ "github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/gcp"
	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/mesh"
)

// Based on krun, start pilot-agent to get the certs and create the XDS proxy, and implement
// a SNI to H2 proxy - similar with the current multi-net gateway protocol from Istio side.
//
// This has a dependency on k8s - will auto-update the WorkloadInstance for H2R.
//
// However it does not depend directly on Istio or XDS - the certificates can be mounted or generated with
// krun+pilot-agent.
func main() {
	kr := mesh.New()

	kr.VendorInit = gcp.InitGCP

	sg := meshconnectord.New(kr)
	err := sg.InitSNIGate(context.Background(), ":15442", ":15441")
	if err != nil {
		log.Fatal("Failed to connect to GKE ", time.Since(kr.StartTime), kr, os.Environ(), err)
	}
	log.Println("Started MeshConnector", os.Environ())

	select {}

}
