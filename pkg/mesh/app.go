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
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
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
			log.Println("Application err exit ", err, cmd.ProcessState.ExitCode(), time.Since(kr.StartTime))
		} else {
			log.Println("Application clean exit ", err, cmd.ProcessState.ExitCode(), time.Since(kr.StartTime))
		}
		kr.Exit(cmd.ProcessState.ExitCode())
	}()

	kr.Signals()
}

// WaitTCPReady uses the same detection as CloudRun, i.e. TCP connect.
func (kr *KRun) WaitTCPReady(addr string, max time.Duration) error {
	t0 := time.Now()
	deadline := t0.Add(max)

	for {
		// if we cant connect, count as fail
		conn, err := net.DialTimeout("tcp", addr, deadline.Sub(time.Now()))
		if err != nil {
			if time.Now().After(deadline) {
				return err
			}
			time.Sleep(50 * time.Millisecond)
			if conn != nil {
				_ = conn.Close()
			}
			continue
		}
		err = conn.Close()
		if err != nil {
			log.Println("WaitTCP.Close()", err)
		}
		log.Println("Application ready", time.Since(t0), time.Since(kr.StartTime))
		return nil
	}
	return nil

}

func (kr *KRun) WaitHTTPReady(url string, max time.Duration) error {
	t0 := time.Now()
	for {
		res, _ := http.Get(url)
		if res != nil && res.StatusCode == 200 {
			log.Println("Ready")
			return nil
		}

		if time.Since(t0) > max {
			return errors.New("Timeout waiting for ready")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

