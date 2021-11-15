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
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"
)

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var Debug = false

// Init klog.InitFlags from an env (to avoid messing with the CLI of
// the app). For example -v=9 lists full request content, -v=7 lists requests headers
func init() {
	fs := &flag.FlagSet{}
	klog.InitFlags(fs)
	kf := strings.Split(os.Getenv("KLOG_FLAGS"), " ")
	fs.Parse(kf)
}

// initUsingKubeConfig uses KUBECONFIG or $HOME/.kube/config
// to init the primary k8s cluster.
//
// error is set if KUBECONFIG is set or ~/.kube/config exists and
// fail to load. If the file doesn't exist, err is nil.
func (kr *KRun) initUsingKubeConfig() error {
	// Explicit kube config - use it
	kc := os.Getenv("KUBECONFIG")
	if kc == "" {
		kc = os.Getenv("HOME") + "/.kube/config"
	}
	if _, err := os.Stat(kc); err == nil {
		cf, err := clientcmd.LoadFromFile(kc)
		//config := clientcmd.NewNonInteractiveClientConfig(cf, cf.CurrentContext, nil, nil)
		if strings.HasPrefix(cf.CurrentContext, "gke_") {
			parts := strings.Split(cf.CurrentContext, "_")
			if len(parts) > 3 {
				// TODO: if env variable with cluster name/location are set - use that for context
				kr.ProjectId = parts[1]
				kr.ClusterLocation = parts[2]
				kr.ClusterName = parts[3]
			}
		}
		if strings.HasPrefix(cf.CurrentContext, "connectgateway_") {
			parts := strings.Split(cf.CurrentContext, "_")
			if len(parts) > 2 {
				// TODO: if env variable with cluster name/location are set - use that for context
				kr.ProjectId = parts[1]
				kr.ClusterName = parts[2]
			}
		}

		config, err := clientcmd.BuildConfigFromFlags("", kc)
		if err != nil {
			return err
		}
		kr.Client, err = kubernetes.NewForConfig(config)
		if err != nil {
			return err
		}

		if Debug {
			log.Println("Using Kubeconfig", cf.CurrentContext, kc)
		}
		return nil
	}
	return nil
}

func (kr *KRun) initInCluster() error {
	if kr.Client != nil {
		return nil
	}
	hostInClustser := os.Getenv("KUBERNETES_SERVICE_HOST")
	if hostInClustser == "" {
		return nil
	}
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err)
	}
	kr.Client, err = kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}
	if Debug {
		log.Println("Using in-cluster k8s ", hostInClustser)
	}
	kr.InCluster = true
	return nil
}

// LoadConfig gets the default k8s client, using environment
// variables to decide how:
//
// - KUBECONFIG or $HOME/.kube/config will be tried first
// - GKE is checked - using env or metadata server to get
//   PROJECT_ID, CLUSTER_LOCATION, CLUSTER_NAME (if not set), and
//   construct a kube config to use.
// - (in future other vendor-specific methods may be added)
// - finally in-cluster will be checked.
//
// Once the cluster is found, additional config can be loaded from
// the cluster.
func (kr *KRun) LoadConfig(ctx context.Context) error {
	mesh := kr.Config("MESH", "")
	if mesh != "" {
		meshURL, err := url.Parse(mesh)
		if err != nil {
			return fmt.Errorf("Invalid meshURL %v %v", mesh, err)
		}
		kr.MeshAddr = meshURL
	}
	// TODO: if meshURL is set and is file:// or gke:// - use it directly

	err := kr.K8SClient(ctx)
	if err != nil {
		return err
	}

	// Load additional settings from env.
	kr.initFromEnv()

	// It is possible to have only one of the 2 mesh connector services installed
	if kr.XDSAddr == "" || kr.ProjectNumber == "" ||
		(kr.MeshConnectorAddr == "" && kr.MeshConnectorInternalAddr == "") {
		err := kr.loadMeshEnv(ctx)
		if err != nil {
			return err
		}
	}

	if kr.ClusterAddress == "" {
		kr.ClusterAddress = fmt.Sprintf("https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s",
			kr.ProjectId, kr.ClusterLocation, kr.ClusterName)
	}
	return err
}

// K8SClient will discover a K8S config cluster.
func (kr *KRun) K8SClient(ctx context.Context) error {
	if kr.Client != nil {
		return nil
	}

	err := kr.initUsingKubeConfig()
	if err != nil {
		return err
	}

	err = kr.initInCluster()
	if err != nil {
		return err
	}

	if kr.VendorInit != nil {
		err = kr.VendorInit(ctx, kr)
		if err != nil {
			return err
		}
	}
	if kr.Client != nil {
		return nil
	}

	return errors.New("not found")
}
