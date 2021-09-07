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
	"io"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	_ "github.com/costinm/cloud-run-mesh/pkg/gcp"
	"github.com/costinm/cloud-run-mesh/pkg/mesh"
	"github.com/costinm/cloud-run-mesh/pkg/hbone"
)

// TestSNIGate is e2e, requires a k8s connection (kube config is fine)
// Also requires certificates to be created - will not start agent or envoy
func xTestSNIGate(t *testing.T) {
	gateK8S := mesh.New("")
	gateK8S.XDSAddr = "-" // prevent pilot-agent from starting
	gateK8S.BaseDir = "../../"

	gate := New(gateK8S)

	err := gate.InitSNIGate(context.Background(), ":0", ":0")
	if err != nil {
		t.Skip("Failed to connect to start gate ", time.Since(gateK8S.StartTime), gateK8S, os.Environ(), err)
	}
	t.Log("Gate listening on ", gate.SNIListener.Addr())

	// Using same credentials - can be a separate service in same namespace
	aliceAuth, err := hbone.NewAuthFromDir("")

	alice := hbone.New(aliceAuth)
	// TODO: use the full URL of CR, and a magic port ?

	aliceToFortio := alice.NewClient("fortio-cr.fortio.svc.cluster.local:8080")
	aliceToFortio.NewEndpoint("")

}

func xTestSNIGateClient(t *testing.T) {
	kr := mesh.New("")
	kr.XDSAddr = "-" // prevent pilot-agent from starting
	kr.BaseDir = "../../"

	ctx, cf := context.WithTimeout(context.Background(), 5*time.Second)
	defer cf()

	err := kr.LoadConfig(ctx)
	if err != nil {
		t.Skip("Skipping test, no k8s environment")
	}

	auth, err := hbone.NewAuthFromDir(kr.BaseDir + "var/run/secrets/istio.io/")
	if err != nil {
		t.Skip("Skipping test, missing certificates.")
	}

	alice := hbone.New(auth)

	addr, err := kr.FindHGate(ctx)
	if err != nil {
		t.Fatal("Error finding gate")
	}
	if addr == "" {
		t.Skip("Missing gate")
	}

	// TODO: use the full URL of CR, and a magic port ?

	t.Run("sni-to-test", func(t *testing.T) {
		aliceToFortio := alice.NewClient("fortio-cr.fortio.svc.cluster.local:8080")

		// Create an endpoint for the gate.
		ep := aliceToFortio.NewEndpoint("https://" + addr + ":15443/_hbone/tcp")
		ep.SNI = "outbound_.8080_._.default.default.svc.cluster.local"

		rin, lout := io.Pipe()
		lin, rout := io.Pipe()

		err = ep.Proxy(context.Background(), rin, rout)
		if err != nil {
			t.Fatal(err)
		}

		lout.Write([]byte("GET / HTTP/1.1\n\n"))
		d, err := ioutil.ReadAll(lin)
		log.Println(d, err)
	})
}

// Manual testing, using the gate on localhost and the e2e test service:

// /usr/bin/curl  -v https://fortio-istio-icq63pqnqq-uc.fortio.svc.cluster.local:15443/fortio/  --resolve fortio-istio-icq63pqnqq-uc.fortio.svc.cluster.local:15443:127.0.0.1 --key var/run/secrets/istio.io/key.pem --cert var/run/secrets/istio.io/cert-chain.pem --cacert var/run/secrets/istio.io/root-cert.pem
// SUFFIX=-istio make -f samples/fortio/Makefile logs |less
