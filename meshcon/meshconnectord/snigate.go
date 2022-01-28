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
	"net"
	"strings"
	"time"

	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/hbone"
	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/k8s"
	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/mesh"
	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/sts"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/client-go/kubernetes"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type MeshConnector struct {
	SNIListener net.Listener
	HBone       *hbone.HBone
	Mesh        *mesh.KRun

	Namespace     string
	ConfigMapName string

	CAPool string
	CASRoots string

	// Primary client is the k8s client to use. If not set will be created based on
	// the config.
	Client *kubernetes.Clientset

	stop     chan struct{}
	Services map[string]*corev1.Service
	EP       map[string]*discoveryv1.EndpointSlice
}

func New(kr *mesh.KRun) *MeshConnector {
	return &MeshConnector{
		Mesh:          kr,
		Namespace:     "istio-system",
		ConfigMapName: "mesh-env",
		EP:            map[string]*discoveryv1.EndpointSlice{},
		Services:      map[string]*corev1.Service{},
		stop:          make(chan struct{}),
	}
}

// InitSNIGate will start the mesh gateway, with a special SNI router port.
// The h2rPort is experimental, for dev/debug, for users running/debugging apps locally.
func (sg *MeshConnector) InitSNIGate(ctx context.Context, sniPort string, h2rPort string) error {
	kr := sg.Mesh

	sg.Client = k8s.K8SClient(kr)

	// Locate a k8s cluster, load configs from env and from existing mesh-env.
	// This will load the existing mesh-env, if it exists.
	err := kr.LoadConfig(ctx)
	if err != nil {
		log.Println("Failed to load config", "err", err)
		return err
	}

	sg.InitMeshEnv(ctx)
	sg.InitMeshEnvGCP(ctx)

	// Default the XDSAddr for the envoy we start to the service created by the hgate install.
	// istiod.istio-system may not be created if 'revision install' is used.
	// This is only used if we operate in 'proxyless' mode in GCP, or as a sidecar to istiod
	if kr.XDSAddr == "" &&
		(kr.MeshTenant == "" || kr.MeshTenant == "-") {
		// Explicitly set XDSAddr, the gate should run in the same cluster
		// with istiod (to forward to istiod), but will use the local in-cluster address.
		kr.XDSAddr = "hgate-istiod.istio-system.svc:15012"
		log.Println("MCP not detected, using hgate-istiod service", kr.MeshTenant)
	}

	if kr.MeshConnectorAddr == "" {
		// We'll need to wait for it - is used when updating the config
		kr.MeshConnectorAddr, err = sg.WaitService(ctx, "hgate")
		if err != nil {
			return err
		}
	}
	if kr.MeshConnectorInternalAddr == "" {
		kr.MeshConnectorInternalAddr, err = sg.WaitService(ctx, "internal-hgate")
		if err != nil {
			return err
		}
	}

	sg.NewWatcher()

	if kr.Gateway == "" {
		kr.Gateway = "hgate"
	}

	err = kr.StartIstioAgent()
	if err != nil {
		log.Fatal("Failed to start istio agent and envoy", err)
	}

	h2r := hbone.New()
	sg.HBone = h2r
	stsc, err := sts.NewSTS(kr)
	if err != nil {
		return err
	}

	tcache := sts.NewTokenCache(kr, stsc)
	h2r.TokenCallback = tcache.Token

	sg.updateMeshEnv(ctx)

	h2r.EndpointResolver = func(sni string) *hbone.Endpoint {
		// Current Istio SNI looks like:
		//
		// outbound_.9090_._.prometheus-1-prometheus.mon.svc.cluster.local
		// We need to map it to a cloudrun external address, add token based on the audience, and make the call using
		// the tunnel.
		//
		// Also supports the 'natural' form

		//
		//
		parts := strings.Split(sni, ".")
		remoteService := parts[0]
		if parts[0] == "outbound_" {
			remoteService = parts[3]
			// TODO: extract 'version' from URL, convert it to cloudrun revision ?
			// TODO: watcher on Service or ServiceEntry ( k8s or XDS ) to get annotation, allowing service name to be different
		}

		base := remoteService + ".a.run.app"
		h2c := h2r.NewClient()
		ep := h2c.NewEndpoint("https://" + base + "/_hbone/15003")
		ep.SNI = base

		return ep
	}

	sg.SNIListener, err = hbone.ListenAndServeTCP(sniPort, h2r.HandleSNIConn)
	if err != nil {
		return err
	}

	return nil
}


// Wait for the hgate and internal hgate service, set the config
func (sg *MeshConnector) WaitService(ctx context.Context, name string) (string, error) {
	for {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		ts, err := sg.Client.CoreV1().Services("istio-system").Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if !Is404(err) {
				log.Println("Error getting service", name, err)
				return "", err
			}
		}

		if ts != nil && len(ts.Status.LoadBalancer.Ingress) > 0 {
			return ts.Status.LoadBalancer.Ingress[0].IP, nil
		}

		time.Sleep(200 * time.Millisecond)
	}
}
