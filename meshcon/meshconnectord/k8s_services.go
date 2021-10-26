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

package meshconnectord

import (
	"context"
	"log"

	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/mesh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConnectHGate will connect to an in-cluster reverse gateway, and maintain the connection.
// Deprecated - loaded from mesh.env, to avoid complexity in the client ( and extra roundtrips/startup delay)
func FindHGate(ctx context.Context, kr *mesh.KRun) (string, error) {

	ts, err := kr.Client.CoreV1().Services("istio-system").Get(ctx, "hgate", metav1.GetOptions{})
	if err != nil {
		log.Println("Error getting service hgate ", err)
		return "", err
	}

	if len(ts.Status.LoadBalancer.Ingress) > 0 {
		return ts.Status.LoadBalancer.Ingress[0].IP, nil
	}

	return "", nil
}
