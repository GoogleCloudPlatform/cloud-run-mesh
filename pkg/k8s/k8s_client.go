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

package k8s

import (
	"context"
	"flag"
	"log"
	"os"
	"strings"

	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/mesh"
	authenticationv1 "k8s.io/api/authentication/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"
)

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var Debug = true

type K8S struct {
	Mesh *mesh.KRun
	Client                                  *kubernetes.Clientset
}

func K8SClient(kr *mesh.KRun) *kubernetes.Clientset {
	if k8s, ok := kr.TokenProvider.(*K8S); ok {
		return k8s.Client
	}
	return nil
}

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
func (kr *K8S) initUsingKubeConfig() error {
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
				kr.Mesh.ProjectId = parts[1]
				kr.Mesh.ClusterLocation = parts[2]
				kr.Mesh.ClusterName = parts[3]
			}
		}
		if strings.HasPrefix(cf.CurrentContext, "connectgateway_") {
			parts := strings.Split(cf.CurrentContext, "_")
			if len(parts) > 2 {
				// TODO: if env variable with cluster name/location are set - use that for context
				kr.Mesh.ProjectId = parts[1]
				kr.Mesh.ClusterName = parts[2]
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

func (kr *K8S) initInCluster() error {
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
	kr.Mesh.InCluster = true
	return nil
}

// K8SClient will discover a K8S config cluster and return the client
func (kr *K8S) K8SClient(ctx context.Context) error {
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

// Read with Secrets and ConfigMaps

func (kr *K8S) GetCM(ctx context.Context, ns string, name string) (map[string]string, error) {
	s, err := kr.Client.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if Is404(err) {
			err = nil
		}
		return map[string]string{}, err
	}

	return s.Data, nil
}

func (kr *K8S) GetSecret(ctx context.Context, ns string, name string) (map[string][]byte, error) {
	s, err := kr.Client.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if Is404(err) {
			err = nil
		}
		return map[string][]byte{}, err
	}

	return s.Data, nil
}

func Is404(err error) bool {
	if se, ok := err.(*k8serrors.StatusError); ok {
		if se.ErrStatus.Code == 404 {
			return true
		}
	}
	return false
}

// GetToken returns a token with the given audience for the current KSA, using CreateToken request.
// Used by the STS token exchanger.
func (kr *K8S) GetToken(ctx context.Context, aud string) (string, error) {
	treq := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences: []string{aud},
		},
	}
	ts, err := kr.Client.CoreV1().ServiceAccounts(kr.Mesh.Namespace).CreateToken(ctx,
		kr.Mesh.KSA, treq, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}

	return ts.Status.Token, nil
}
