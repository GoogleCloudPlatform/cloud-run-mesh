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
	"errors"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/costinm/cloud-run-mesh/pkg/hbone"
	"github.com/costinm/cloud-run-mesh/pkg/mesh"
	"github.com/costinm/cloud-run-mesh/pkg/sts"
	"golang.org/x/net/http2"

	corev1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type MeshConnector struct {
	SNIListener net.Listener
	H2RListener net.Listener
	Auth        *hbone.Auth
	HBone       *hbone.HBone
	Mesh        *mesh.KRun

	Namespace   string
	ConfigMapName string

	stop chan struct{}
}


type cachedToken struct {
	token      string
	expiration time.Time
}

type TokenCache struct {
	cache sync.Map
	kr    *mesh.KRun
	sts   *sts.STS
}

func (c TokenCache) Token(ctx context.Context, host string) (string, error) {

	if got, f := c.cache.Load(host); f {
		t := got.(cachedToken)
		if !t.expiration.After(time.Now().Add(-time.Minute)) {
			return t.token, nil
		}
	}

	mt, err := c.sts.GetRequestMetadata(ctx, host)
	if err != nil {
		return "", err
	}
	bt := mt["authorization"]
	if !strings.HasPrefix(bt, "Bearer ") {
		return "", errors.New("Invalid prefix")
	}
	t := bt[7:]
	//log.Println("XXX debug Gettoken from metadata", host, k8s.TokenPayload(t), err)

	c.cache.Store(host, cachedToken{t, time.Now().Add(45 * time.Minute)})
	return t, nil
}

func New(kr *mesh.KRun) *MeshConnector {
	return &MeshConnector{
		Mesh: kr,
		Namespace: "istio-system",
		ConfigMapName: "mesh-env",
		stop : make(chan struct{}),
	}
}


func (sg *MeshConnector) InitSNIGate(ctx context.Context, sniPort string, h2rPort string) error {
	kr := sg.Mesh
	// Locate a k8s cluster
	err := kr.LoadConfig(ctx)
	if err != nil {
		return err
	}

	if kr.XDSAddr == "" {
		err = sg.FindXDSAddr(ctx)
		if err != nil {
			return err
		}
	}

	if kr.MeshConnectorAddr == "" {
		// We'll need to wait for it - is used when updating the config
		err := sg.WaitService(ctx)
		if err != nil {
			return err
		}
	}
	if kr.MeshConnectorInternalAddr == "" {
		err := sg.WaitInternalService(ctx)
		if err != nil {
			return err
		}
	}

	citadelRoot, err := sg.GetCARoot(ctx)
	if err != nil {
		return err
	}
	if citadelRoot != "" {
		kr.CitadelRoot = citadelRoot
	}

	// create the tokens expected for Istio (token)
	kr.RefreshAndSaveFiles()

	sg.NewWatcher()

	if kr.Gateway == "" {
		kr.Gateway = "hgate"
	}

	err = kr.StartIstioAgent()
	if err != nil {
		log.Fatal("Failed to start istio agent and envoy", err)
	}

	// Will use istio-agent created certs for now. WIP: run the
	// gate without pilot-agent/envoy, will use built-in CA providers.
	auth, err := hbone.NewAuthFromDir(kr.BaseDir + "var/run/secrets/istio.io/")
	if err != nil {
		return  err
	}

	// All namespaces are allowed to connect.
	auth.AllowedNamespaces = []string{"*"}

	sg.Auth = auth
	h2r := hbone.New(auth)
	sg.HBone = h2r
	stsc, err := sts.NewSTS(kr)
	if err != nil {
		return  err
	}

	tcache := &TokenCache{kr: kr, sts: stsc}
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
		log.Println("Endpoint resolver, h2r not found", parts)

		base := remoteService + ".a.run.app"
		h2c := h2r.NewClient(sni)
		ep := h2c.NewEndpoint("https://" + base + "/_hbone/mtls")
		ep.SNI = base

		return ep
	}

	h2r.H2RCallback = func(s string, conn *http2.ClientConn) {
		if s == "" {
			return
		}
		log.Println("H2R connection event", s, conn)

		// TODO: save a WorkloadInstance of EndpontSlice

	}

	sg.SNIListener, err = hbone.ListenAndServeTCP(sniPort, h2r.HandleSNIConn)
	if err != nil {
		return  err
	}

	sg.H2RListener, err = hbone.ListenAndServeTCP(h2rPort, h2r.HandlerH2RConn)
	if err != nil {
		return err
	}

	return nil
}

func FindInClusterAddr(ctx context.Context, kr *mesh.KRun) error {
	hg, err := kr.FindHGate(ctx)
	if err != nil {
		if mesh.Is404(err) {
			return nil // no error, but no address either
		}
		log.Println("Failed to find in-cluster, missing 'hgate' service ", err)
		return err
	}

	kr.XDSAddr = hg + ":15012"

	return nil
}

func (sg *MeshConnector) GetCARoot(ctx context.Context) (string, error){
	// TODO: depending on error, move on or report a real error
	kr := sg.Mesh
	cm, err := kr.GetCM(ctx, "istio-system", "istio-ca-root-cert")
	if err != nil {
		if mesh.Is404(err) {
			return "", nil
		}
		return "", err
	} else {
		// normally mounted to /var/run/secrets/istio
		rootCert := cm["root-cert.pem"]
		if rootCert == "" {
			return "", nil
		} else {
			return rootCert, nil
		}
	}
}


// FindXDSAddr will try to find the XDSAddr using in-cluster info.
// This is called after K8S client has been initialized.
//
// For MCP, will expect a config map named 'env-asm-managed'
// For in-cluster, we'll lookup the connector's LB, which points to istio.istio-system.svc
//
// This depends on MCP and Istiod internal configs - the config map may set with the XDS_ADDR and associated configs, in
// which case this will not be called.
func (sg *MeshConnector) FindXDSAddr(ctx context.Context) error {
	kr := sg.Mesh
	if kr.ProjectNumber == "" {
		log.Println("MCP requires PROJECT_NUMBER, attempting to use in-cluster")
		return FindInClusterAddr(ctx, kr)
	}
	cmname := os.Getenv("MCP_CONFIG")
	if cmname == "" {
		cmname = "env-asm-managed"
	}
	// TODO: find default tag, label, etc.
	// Current code is written for MCP, use XDS_ADDR explicitly
	// otherwise.
	s, err := kr.Client.CoreV1().ConfigMaps("istio-system").Get(ctx,
		cmname, metav1.GetOptions{})
	if err != nil {
		if mesh.Is404(err) {
			return FindInClusterAddr(ctx, kr)
		}
		return err
	}

	kr.MeshTenant = s.Data["CLOUDRUN_ADDR"]
	kr.XDSAddr = "meshconfig.googleapis.com:443"
	log.Println("Istiod MCP discovered ", kr.MeshTenant, kr.XDSAddr,
		kr.ProjectId, kr.ProjectNumber, kr.TrustDomain)

	return nil
}

func (sg *MeshConnector) updateMeshEnv(ctx context.Context) error {
	cmAPI := sg.Mesh.Client.CoreV1().ConfigMaps(sg.Namespace)
	cm, err := cmAPI.Get(ctx, "mesh-env", metav1.GetOptions{})
	if err != nil {
		if !mesh.Is404(err) {
			return err
		}
		// Not found, create:
		cm = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mesh-env",
				Namespace: "istio-system",
			},
			Data: map[string]string{},
		}
		sg.Mesh.SaveToMap(cm.Data)
		_, err = cmAPI.Create(ctx, cm, metav1.CreateOptions{})
		if err != nil {
			log.Println("Failed to update config map, skipping ", err)
		}
		return nil
	}

	if !sg.Mesh.SaveToMap(cm.Data) {
		return nil
	}
	_, err = cmAPI.Update(ctx, cm, metav1.UpdateOptions{})
	if err != nil {
		log.Println("Failed to update config map, skipping ", err)
	} else {
		log.Println("Update mesh env with defaults")
	}
	return nil
}

// Wait for the hgate and internal hgate service, set the config
func (sg *MeshConnector) WaitService(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		kr := sg.Mesh
		ts, err := kr.Client.CoreV1().Services("istio-system").Get(ctx, "hgate", metav1.GetOptions{})
		if err != nil {
			if !mesh.Is404(err) {
				log.Println("Error getting service hgate ", err)
				return err
			}
		}

		if ts != nil && len(ts.Status.LoadBalancer.Ingress) > 0 {
			sg.Mesh.MeshConnectorAddr = ts.Status.LoadBalancer.Ingress[0].IP
			return nil
		}

		time.Sleep(200 * time.Millisecond)
	}
}

func (sg *MeshConnector) WaitInternalService(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		kr := sg.Mesh
		ts, err := kr.Client.CoreV1().Services("istio-system").Get(ctx, "internal-hgate", metav1.GetOptions{})
		if err != nil {
			if !mesh.Is404(err) {
				log.Println("Error getting service hgate ", err)
				return err
			}
		}

		if ts != nil && len(ts.Status.LoadBalancer.Ingress) > 0 {
			sg.Mesh.MeshConnectorInternalAddr = ts.Status.LoadBalancer.Ingress[0].IP
			return nil
		}

		time.Sleep(200 * time.Millisecond)
	}
}

