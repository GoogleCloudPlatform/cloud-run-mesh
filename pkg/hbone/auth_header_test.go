// Copyright 2024 Google LLC
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
	"io"
	"net"
	"net/http"
	"sync"
	"testing"

	"golang.org/x/net/http2"
)

const fakeIAMToken = "fake-iam-token"

// captureServer starts a raw H2C server that records the headers of every
// incoming request and responds 200 OK. Returns the listener address and a
// function to retrieve the captured header slices.
func captureServer(t *testing.T) (addr string, headers func() []http.Header) {
	t.Helper()
	var mu sync.Mutex
	var captured []http.Header

	srv := &http2.Server{}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go srv.ServeConn(conn, &http2.ServeConnOpts{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					captured = append(captured, r.Header.Clone())
					mu.Unlock()
					// Drain body so the client Proxy call can complete.
					io.Copy(io.Discard, r.Body)
					w.WriteHeader(http.StatusOK)
				}),
			})
		}
	}()

	return l.Addr().String(), func() []http.Header {
		mu.Lock()
		defer mu.Unlock()
		cp := make([]http.Header, len(captured))
		copy(cp, captured)
		return cp
	}
}

// newClientWithToken returns an HBone client whose TokenCallback always returns fakeIAMToken.
func newClientWithToken() *HBone {
	hb := New()
	hb.TokenCallback = func(_ context.Context, _ string) (string, error) {
		return fakeIAMToken, nil
	}
	return hb
}

// TestTokenInjection_NoExistingAuth verifies that when the caller does not set
// an Authorization header on the Endpoint, the IAM token is placed in
// Authorization (existing behaviour).
func TestTokenInjection_NoExistingAuth(t *testing.T) {
	addr, getHeaders := captureServer(t)

	alice := newClientWithToken()
	ep := alice.NewEndpoint("http://" + addr + "/_hbone/tcp")
	// No ep.Headers set — no pre-existing Authorization.

	rin, wout := io.Pipe()
	wout.Close() // empty body so Proxy returns quickly

	_, rout := io.Pipe()
	defer rout.Close()

	_ = ep.Proxy(context.Background(), rin, rout)

	hdrs := getHeaders()
	if len(hdrs) == 0 {
		t.Fatal("server received no requests")
	}
	got := hdrs[0]
	if got.Get("Authorization") != "Bearer "+fakeIAMToken {
		t.Errorf("Authorization = %q, want %q", got.Get("Authorization"), "Bearer "+fakeIAMToken)
	}
	if got.Get("X-Serverless-Authorization") != "" {
		t.Errorf("X-Serverless-Authorization should be empty, got %q", got.Get("X-Serverless-Authorization"))
	}
}

// TestTokenInjection_WithExistingAuth verifies that when the caller sets an
// Authorization header on the Endpoint (e.g. to forward a user JWT through a
// service chain), the IAM token is placed in X-Serverless-Authorization and
// the original Authorization header is preserved unchanged.
func TestTokenInjection_WithExistingAuth(t *testing.T) {
	addr, getHeaders := captureServer(t)

	const userJWT = "user-jwt-abc123"

	alice := newClientWithToken()
	ep := alice.NewEndpoint("http://" + addr + "/_hbone/tcp")
	ep.Headers = http.Header{
		"Authorization": {"Bearer " + userJWT},
	}

	rin, wout := io.Pipe()
	wout.Close()

	_, rout := io.Pipe()
	defer rout.Close()

	_ = ep.Proxy(context.Background(), rin, rout)

	hdrs := getHeaders()
	if len(hdrs) == 0 {
		t.Fatal("server received no requests")
	}
	got := hdrs[0]
	if got.Get("Authorization") != "Bearer "+userJWT {
		t.Errorf("Authorization = %q, want original user JWT %q", got.Get("Authorization"), "Bearer "+userJWT)
	}
	if got.Get("X-Serverless-Authorization") != "Bearer "+fakeIAMToken {
		t.Errorf("X-Serverless-Authorization = %q, want %q", got.Get("X-Serverless-Authorization"), "Bearer "+fakeIAMToken)
	}
}
