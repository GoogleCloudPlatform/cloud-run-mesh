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
	"log"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// CheckServices will look for istiod, hgate and the debug service.
//
// TODO: detect istiod service (in-cluster), use it if external is not configured
// TODO: detect cert-ssh, use it to enable debug
func (kr *KRun) CheckServices(ctx context.Context, client *kubernetes.Clientset) error {
	ts, err := client.CoreV1().Services("istio-system").List(ctx,
		metav1.ListOptions{})
	if err != nil {
		log.Println("Error listing ", err)
		return err
	}

	for _, s := range ts.Items {
		if s.Name == "cert-ssh" {
			log.Println("Found cert-ssh", s.Status)
		}
		if strings.HasPrefix(s.Name, "istiod") {
			log.Println("Found istiod", s.Name, s.Status)
		}
	}
	return nil
}

// ConnectHGate will connect to an in-cluster reverse gateway, and maintain the connection.
// Deprecated - loaded from mesh.env, to avoid complexity in the client ( and extra roundtrips/startup delay)
func (kr *KRun) FindHGate(ctx context.Context) (string, error) {

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
