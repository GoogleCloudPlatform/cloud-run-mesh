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

package main

import (
	"context"
	"log"

	"github.com/costinm/cert-ssh/ssh"
	"github.com/costinm/cloud-run-mesh/pkg/mesh"
)

// Optional debug dependency, using cert-based SSH or loaded from a secret.
// TODO: add conditional compilation, or move it to a separate binary that can be forked

func init() {
	initDebug = InitDebug
}

func InitDebug(kr *mesh.KRun) {
	sshCM, err := kr.GetSecret(context.Background(), kr.Namespace, "sshdebug")
	if err != nil {
		log.Println("SSH config error", err)
	}
	ssh.InitFromSecret(sshCM, kr.Namespace)
}
