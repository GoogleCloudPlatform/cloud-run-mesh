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
	"io/ioutil"
	"os"
	"path/filepath"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	kubeconfig "k8s.io/client-go/tools/clientcmd/api"
)

// Utilities around kube config

// SaveKubeConfig saves the KUBECONFIG to ./var/run/.kube/config
// The assumption is that on a read-only image, /var/run will be
// writeable and not backed up.
func SaveKubeConfig(kc *kubeconfig.Config, dir, file string) error {
	cfgjs, err := clientcmd.Write(*kc)
	if err != nil {
		return err
	}
	err = os.MkdirAll(dir, 0755)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath.Join(dir, file), cfgjs, 0744)
	if err != nil {
		return err
	}
	return nil
}

func restConfig(kc *kubeconfig.Config) (*rest.Config, error) {
	// TODO: set default if not set ?
	return clientcmd.NewNonInteractiveClientConfig(*kc, "", &clientcmd.ConfigOverrides{}, nil).ClientConfig()
}

func MergeKubeConfig(dst *kubeconfig.Config, src *kubeconfig.Config) {
	for k, c := range src.Clusters {
		dst.Clusters[k] = c
	}
	for k, c := range src.Contexts {
		dst.Contexts[k] = c
	}
	for k, c := range src.AuthInfos {
		dst.AuthInfos[k] = c
	}
}
