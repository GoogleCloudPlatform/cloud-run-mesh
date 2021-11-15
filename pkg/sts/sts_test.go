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

package sts

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	_ "github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/gcp"
	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/mesh"
)

// TestSTS uses a k8s connection and env to locate the mesh, and tests the token generation.
func TestSTS(t *testing.T) {
	kr := mesh.New()

	ctx, cf := context.WithTimeout(context.Background(), 10*time.Second)
	defer cf()

	err := kr.LoadConfig(ctx)
	if err != nil {
		t.Skip("Failed to connect to GKE, missing kubeconfig ", time.Since(kr.StartTime), kr, os.Environ(), err)
	}

	if kr.ProjectNumber == "" {
		t.Skip("Skipping STS test, PROJECT_NUMBER required")
	}
	masterT, err := kr.GetToken(ctx, kr.TrustDomain)
	if err != nil {
		t.Fatal(err)
	}

	log.Println(mesh.TokenPayload(masterT))

	s, err := NewSTS(kr)
	if err != nil {
		t.Fatal(err)
	}

	f, err := s.TokenFederated(ctx, masterT)
	if err != nil {
		t.Fatal(err)
	}

	a, err := s.TokenAccess(ctx, f, "")
	if err != nil {
		t.Fatal(err)
	}

	a, err = s.TokenAccess(ctx, f, "https://foo.bar")
	if err != nil {
		t.Fatal(err)
	}
	log.Println(mesh.TokenPayload(a))
}
