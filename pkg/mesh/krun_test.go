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
	context2 "context"
	"os"
	"testing"
	"time"

	// Required for k8s client to link in the authenticator
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

// Requires KUBECONFIG or $HOME/.kube/config
// The cluster must have MCP enabled.
// The test environment must have envoy in /usr/local/bin
func TestK8S(t *testing.T) {
	os.Mkdir("../../../out", 0775)
	os.Chdir("../../../out")

	kr := New()

	err := kr.LoadConfig(context2.Background())
	if err != nil {
		t.Skip("Failed to connect to GKE, missing kubeconfig ", time.Since(kr.StartTime), kr, os.Environ(), err)
	}

	// For Istio agent
	kr.RefreshAndSaveTokens()

	kr.StartIstioAgent()

	t.Log(kr)

}
