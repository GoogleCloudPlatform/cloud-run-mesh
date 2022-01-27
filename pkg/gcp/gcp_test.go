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

package gcp

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/k8s"
	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/mesh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Requires GOOGLE_APPLICATION_CREDENTIALS or metadata server and PROJECT_ID
// The GCP SA must have k8s api permission.
func TestK8S(t *testing.T) {
	os.Mkdir("../../out", 0775)
	os.Chdir("../../out")

	// For the entire test
	ctx, cf := context.WithTimeout(context.Background(), 100*time.Second)
	defer cf()

	kr := mesh.New()

	// If running in GCP, get ProjectId from meta
	configFromEnvAndMD(ctx, kr)

	projectID := kr.ProjectId
	if projectID == "" {
		// Attempt to use the kubeconfig
		kr1 := mesh.New()
		kr1.LoadConfig(ctx)
		if kr1.ProjectId == "" {
			t.Skip("Missing PROJECT_ID")
			return
		}
		kr.ProjectId = kr1.ProjectId
	}

	t.Run("all-any", func(t *testing.T) {
		cl, err := AllClusters(ctx, kr, "", "", "")
		if err != nil {
			t.Fatal(err)
		}
		if len(cl) == 0 {
			t.Fatal("No ASM clusters")
		}
	})
	t.Run("all-mesh-id", func(t *testing.T) {
		cl, err := AllClusters(ctx, kr, "", "mesh_id", "")
		if err != nil {
			t.Fatal(err)
		}
		if len(cl) == 0 {
			t.Fatal("No ASM clusters")
		}
	})

	cl, err := AllClusters(ctx, kr, "", "mesh_id", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cl) == 0 {
		cl, err = AllClusters(ctx, kr, "", "", "")
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(cl) == 0 {
		t.Fatal("No clusters in " + kr.ProjectId)
	}

	testCluster := cl[0]

	// Run the tests on the first found cluster, unless the test is run with env variables to select a specific
	// location and cluster name.

	t.Run("gke", func(t *testing.T) {
		// This is the main function for the package - given a KRun object, initialize the K8S Client based
		// on settings and GKE API result.
		kr1 := mesh.New()
		kr1.ProjectId = kr.ProjectId
		kr1.ClusterName = testCluster.ClusterName
		kr1.ClusterLocation = testCluster.ClusterLocation

		err = InitGCP(context.Background(), kr1)
		if err != nil {
			t.Fatal(err)
		}
		if k8s.K8SClient(kr1) == nil {
			t.Fatal("No client")
		}

		err = checkClient(k8s.K8SClient(kr1))
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("configCluster", func(t *testing.T) {
		kr1 := mesh.New()
		kr1.MeshAddr, _ = url.Parse("gke://" + kr.ProjectId)

		err = InitGCP(context.Background(), kr1)
		if err != nil {
			t.Fatal(err)
		}
		if k8s.K8SClient(kr1) == nil {
			t.Fatal("No client")
		}

		err = checkClient(k8s.K8SClient(kr1))
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("configClusterExplicit", func(t *testing.T) {
		kr1 := mesh.New()
		kr1.MeshAddr, _ = url.Parse(fmt.Sprintf("https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s", kr.ProjectId, kr.ClusterLocation, kr.ClusterName))

		err = InitGCP(context.Background(), kr1)
		if err != nil {
			t.Fatal(err)
		}
		if k8s.K8SClient(kr1) == nil {
			t.Fatal("No client")
		}

		err = checkClient(k8s.K8SClient(kr1))
		if err != nil {
			t.Fatal(err)
		}
	})

}

func checkClient(kc *kubernetes.Clientset) error {
	v, err := kc.ServerVersion() // /version on the server
	if err != nil {
		return err
	}
	log.Println("Cluster version", v)

	_, err = kc.CoreV1().ConfigMaps("istio-system").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	return nil
}
