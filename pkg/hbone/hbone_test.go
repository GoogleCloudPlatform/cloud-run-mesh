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
	"errors"
	"io"
	"log"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/echo"
)

// WIP
func TestHBone(t *testing.T) {
	alice := New()

	bob := New()
	l, err := ListenAndServeTCP(":0", bob.HandleAcceptedH2C)
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
	bob.Ports["tcp"] = ehL.Addr().String()

	// Alice opens hbone to TCP connection to bob's echo server.
	t.Run("plain-alice-bob", func(t *testing.T) {
		rin, lout := io.Pipe()
		lin, rout := io.Pipe()
		go func() {
			err = alice.Proxy("default.bob:8080", "http://"+bobHBAddr+"/_hbone/tcp", rin, rout)
			if err != nil {
				t.Fatal(err)
			}
		}()

		EchoClient(t, lout, lin)
	})

	// Server-close does not work with plain text and go http stack.
	// The original packet had a test, using https.
	// We are only using TLS over HTTP/2, which has a special close sequence

	// SNI gate no longer tested here - the package only has barebone plain text
	// support, since TLS handling moved to envoy. E2E tests will cover this part,
	// the full hbone package upstream continues to have coverage.
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
