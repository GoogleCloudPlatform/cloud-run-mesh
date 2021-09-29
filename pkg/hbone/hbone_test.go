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

package hbone

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/costinm/cloud-run-mesh/pkg/echo"
)

// WIP
func TestHBone(t *testing.T) {
	// New self-signed root CA
	ca := NewCA("cluster.local")

	alice := New(ca.NewID("alice", "default"))
	alice.Auth.AllowedNamespaces = []string{"*"}

	bob := New(ca.NewID("bob", "default"))
	bob.Auth.AllowedNamespaces = []string{"*"}
	l, err := ListenAndServeTCP(":0", bob.HandleAcceptedH2)
	if err != nil {
		t.Fatal(err)
	}
	bobHBAddr := l.Addr().String()

	// Start an echo handler on bob
	eh := &echo.EchoHandler{Debug: Debug}
	ehL, err := eh.Start(":0")
	if err != nil {
		t.Fatal(err)
	}
	bob.TcpAddr = ehL.Addr().String()

	// Alice opens hbone to TCP connection to bob's echo server.
	t.Run("plain-alice-bob", func(t *testing.T) {
		rin, lout := io.Pipe()
		lin, rout := io.Pipe()
		go func() {
			err = alice.Proxy("default.bob:8080", "https://"+bobHBAddr+"/_hbone/tcp", rin, rout, nil)
			if err != nil {
				t.Fatal(err)
			}
		}()

		EchoClient(t, lout, lin)
	})

	t.Run("server-close", func(t *testing.T) {
		rin, lout := io.Pipe()
		lin, rout := io.Pipe()
		go func() {
			err = alice.Proxy("default.bob:8080", "https://"+bobHBAddr+"/_hbone/mtls", rin, rout, alice.Auth.MeshTLSConfig)

			//err = alice.Proxy("default.bob:8080", "https://"+bobHBAddr+"/_hbone/tcp", rin, rout, nil)
			if err != nil {
				t.Fatal(err)
			}
		}()

		EchoClient(t, lout, lin)
		log.Println(eh.Received)
		lout.Write([]byte{0})
		log.Println(eh.Received)

		data := make([]byte, 1024)
		r, err := lin.Read(data)
		log.Println("Read: ", r, err)

		lout.Write([]byte("PostClose"))
		log.Println(eh.Received)
	})

	// Evie opens hbone to TCP connection to bob's echo server.
	t.Run("invalid-root", func(t *testing.T) {
		evieca := NewCA("cluster.local")

		evie := New(evieca.NewID("alice", "default"))

		rin, _ := io.Pipe()
		_, rout := io.Pipe()
		err = evie.Proxy("default.bob:8080", "https://"+bobHBAddr+"/_hbone/tcp", rin, rout, nil)
		if err == nil {
			t.Fatal("Expecting error")
		}

	})

	t.Run("invalid-trust", func(t *testing.T) {
		evieca := NewCA("notcluster.local")
		// Using the same root CA as bob/alice
		evieca.ca = ca.ca
		evieca.CACert = ca.CACert

		evie := New(evieca.NewID("alice", "default"))

		rin, _ := io.Pipe()
		_, rout := io.Pipe()
		err = evie.Proxy("default.bob:8080", "https://"+bobHBAddr+"/_hbone/tcp", rin, rout, nil)
		if err == nil {
			t.Fatal("Expecting error")
		}

	})

	// Verify server first protocols work
	t.Run("plain-alice-bob-serverFirst", func(t *testing.T) {
		ehServerFirst := &echo.EchoHandler{ServerFirst: true, Debug: Debug}
		ehSFL, err := ehServerFirst.Start(":0")
		if err != nil {
			t.Fatal(err)
		}
		bob.Mux.HandleFunc("/_hbone/serverFirst", func(w http.ResponseWriter, r *http.Request) {
			err := bob.HandleTCPProxy(w, r.Body, ehSFL.Addr().String())
			log.Println("hbone serverFirst proxy done ", r.RequestURI, err)
		})

		rin, lout := io.Pipe()
		lin, rout := io.Pipe()
		go func() {
			err = alice.Proxy("default.bob:6000", "https://"+bobHBAddr+"/_hbone/serverFirst", rin, rout, nil)
			if err != nil {
				t.Fatal(err)
			}
		}()
		b := make([]byte, 1024)
		n, err := lin.Read(b)
		if n == 0 || err != nil {
			t.Fatal(n, err)
		}
		EchoClient(t, lout, lin)

		// Close client connection - expect FIN to be propagated to echo server, which will close it's out connection,
		// and we should receive io.EOF
		lout.Close()

		n, err = lin.Read(b)
		if err == nil {
			t.Fatal("Missing close")
		}
	})

	t.Run("mtls-alice-bob", func(t *testing.T) {
		rin, lout := io.Pipe()
		lin, rout := io.Pipe()
		go func() {
			err = alice.Proxy("default.bob:8080", "https://"+bobHBAddr+"/_hbone/mtls", rin, rout, alice.Auth.MeshTLSConfig)
			if err != nil {
				t.Fatal(err)
			}
		}()
		EchoClient(t, lout, lin)
	})

	// SNI and H2R gate
	gate := New(ca.NewID("gate", "default"))
	gate.Auth.AllowedNamespaces = []string{"*"}

	t.Run("sni-alice-gate-bob", func(t *testing.T) {
		gateSNIL, err := ListenAndServeTCP(":0", gate.HandleSNIConn)
		if err != nil {
			t.Fatal(err)
		}

		rin, lout := io.Pipe()
		lin, rout := io.Pipe()
		gate.EndpointResolver = func(sni string) *Endpoint {
			gc := gate.NewEndpoint("https://" + bobHBAddr + "/_hbone/mtls")

			return gc
		}

		go func() {
			// 13022 is the SNI port of the gateway. It'll pass-through to the resolved address.
			c := alice.NewEndpoint("https://" + gateSNIL.Addr().String() + "/_hbone/tcp")
			c.SNI = "bob"
			c.SNIGate = gateSNIL.Addr().String()
			err = c.Proxy(context.Background(), rin, rout)
			if err != nil {
				t.Fatal(err)
			}
		}()

		EchoClient(t, lout, lin)
	})

	t.Run("sni-h2r-alice-gate-bob", func(t *testing.T) {
		gateH2RL, err := ListenAndServeTCP(":0", gate.HandlerH2RConn)
		if err != nil {
			t.Fatal(err)
		}
		gateH2RSNIL, err := ListenAndServeTCP(":0", gate.HandleH2RSNIConn)
		if err != nil {
			t.Fatal(err)
		}

		// Connect bob to the gate.
		// ...
		h2rc := bob.NewClient("gate.gate:13222")

		// May have multiple h2r endpoints, to different instances (or all instances, if the gate is a stateful
		// set).
		h2re := h2rc.NewEndpoint("")
		h2re.SNI = "default.bob.svc"

		h2rCtx, h2rCancel := context.WithCancel(context.Background())

		h2rCon, err := h2re.DialH2R(h2rCtx, gateH2RL.Addr().String())
		if err != nil {
			t.Fatal(err)
		}

		// Need to wait for the connection to show up - else the test is flaky
		// TODO: add a callback for 'h2r connection change', will be used to update
		// database.
		for i := 0; i < 10; i++ {
			if gate.H2R[h2re.SNI] == nil {
				time.Sleep(100 * time.Millisecond)
			} else {
				break
			}
		}

		rin, lout := io.Pipe()
		lin, rout := io.Pipe()
		go func() {
			// The endpoint looks like an Istio endpoint.
			//
			c := alice.NewEndpoint("https://" + gateH2RSNIL.Addr().String() + "/_hbone/tcp")
			c.SNI = "default.bob.svc"
			c.SNIGate = gateH2RSNIL.Addr().String()

			err = c.Proxy(context.Background(), rin, rout)
			if err != nil {
				t.Fatal(err)
			}
		}()

		EchoClient(t, lout, lin)

		// Force close the tls con - server should terminate
		h2rCon.Close()

		h2rCancel()
	})
}

func EchoClient(t *testing.T, lout *io.PipeWriter, lin *io.PipeReader) {
	b := make([]byte, 1024)
	timer := time.AfterFunc(3*time.Second, func() {
		log.Println("timeout")
		lin.CloseWithError(errors.New("timeout"))
		lout.CloseWithError(errors.New("timeout"))
	})
	lout.Write([]byte("Ping"))
	n, err := lin.Read(b)
	if n != 4 {
		t.Error(n, err)
	}
	timer.Stop()
}
