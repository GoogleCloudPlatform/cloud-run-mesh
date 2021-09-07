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
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// StartApp uses the reminder of the command line to exec an app, using K8S_UID as UID, if present.
func (kr *KRun) StartApp() {
	var cmd *exec.Cmd
	if len(os.Args) == 1 {
		return
	} else if len(os.Args) == 2 {
		cmd = exec.Command(os.Args[1])
	} else {
		cmd = exec.Command(os.Args[1], os.Args[2:]...)
	}
	if os.Getuid() == 0 {
		uid := os.Getenv("K8S_UID")
		if uid != "" {
			uidi, err := strconv.Atoi(uid)
			if err == nil {
				cmd.SysProcAttr = &syscall.SysProcAttr{}
				cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uidi)}
			}
		}
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Set port to 8080 - some apps use the PORT from knative to start.a
	cmd.Env = []string{"PORT=8080"}
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "PORT=") {
			continue
		}
		cmd.Env = append(cmd.Env, e)
	}
	if os.Getenv("GRPC_XDS_BOOTSTRAP") == "" {
		cmd.Env = append(cmd.Env, "GRPC_XDS_BOOTSTRAP=/var/run/grpc_bootstrap.json")
	}
	if kr.WhiteboxMode {
		cmd.Env = append(cmd.Env, "HTTP_PROXY=127.0.0.1:15007")
		cmd.Env = append(cmd.Env, "http_proxy=127.0.0.1:15007")
	}

	go func() {
		err := cmd.Start()
		if err != nil {
			log.Println("Failed to start ", cmd, err)
		}
		kr.appCmd = cmd
		err = cmd.Wait()
		if err != nil {
			log.Println("Failed to wait ", cmd, err)
		}
		kr.Exit(0)
	}()
}
