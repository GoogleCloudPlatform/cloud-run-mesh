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
	"fmt"
	"io/ioutil"
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

const (
	serverStateKey        = "server.state"
	serverStateCheckRegex = "^server.state"
	listenerCheckKey      = "listener_manager.workers_started"
	listenerCheckRegex    = "^listener_manager.workers_started"
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
		cmd.Env = append(cmd.Env, "GRPC_XDS_BOOTSTRAP=/etc/istio/proxy/grpc_bootstrap.json")
		// This is set by injector
		cmd.Env = append(cmd.Env, "GRPC_XDS_EXPERIMENTAL_RBAC=true")
		cmd.Env = append(cmd.Env, "GRPC_XDS_EXPERIMENTAL_SECURITY_SUPPORT=true")
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

// WaitAppStartup waits for app to be ready to accept requests.
// - default is KNative 'listen on the app port' ( 8080 default, PORT_http overrides )
// - startupProbe.tcp and startupProbe.http can define alternate port and using http ready.
func (kr *KRun) WaitAppStartup() error {
	var err error
	startupTimeout := 10 * time.Second // TODO: make customizable
	// PORT_http is used as an alternative to PORT - which is taken over by the tunnel.
	appPort := kr.Config("PORT_http", "8080")
	// Wait for app to be ready
	startupProbeHttp := kr.Config("startupProbe.http", "")
	startupProbeTcp := kr.Config("startupProbe.tcp", "")
	if startupProbeHttp != "" {
		err = kr.WaitHTTPReady(startupProbeHttp, startupTimeout)
	} else if startupProbeTcp != "" {
		err = kr.WaitTCPReady(startupProbeTcp, startupTimeout)
	} else if appPort != "-" && len(os.Args) > 1 {
		err = kr.WaitTCPReady("127.0.0.1:" + appPort, startupTimeout)
	}
	return err
}

func (kr *KRun) WaitHTTPReady(url string, max time.Duration) error {
	t0 := time.Now()
	for {
		res, _ := http.Get(url)
		if res != nil && res.StatusCode == 200 {
			return nil
		}

		if time.Since(t0) > max {
			return errors.New("Timeout waiting for ready")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// WaitEnvoyReady waits for envoy to be ready until max is reached, otherwise returns a non-nil error.
func (kr *KRun) WaitEnvoyReady(addr string, max time.Duration) error {
	t0 := time.Now()
	for {
		serverStateReady, serverStateErr := kr.envoyServerStateCheck(addr)
		listenerReady, listenerErr := kr.envoyListenerWorkersStartedCheck(addr)
		if serverStateErr == nil && listenerErr == nil && serverStateReady && listenerReady {
			log.Println("Envoy is ready")
			return nil
		}

		if time.Since(t0) > max {
			return fmt.Errorf("Timeout waiting for ready from envoy")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (kr *KRun) envoyServerStateCheck(addr string) (bool, error) {
	checkURL := fmt.Sprintf("http://%s/stats?used_only&filter=%s", addr, serverStateCheckRegex)
	res, err := http.Get(checkURL)
	if err != nil {
		return false, fmt.Errorf("Unable to check envoy server state because of %s", err)
	}
	defer res.Body.Close()
	return kr.processHealthCheckResponse(res, serverStateKey, "0") // 0 indicates live.
}

func (kr *KRun) envoyListenerWorkersStartedCheck(addr string) (bool, error) {
	checkURL := fmt.Sprintf("http://%s/stats?used_only&filter=%s", addr, listenerCheckRegex)
	res, err := http.Get(checkURL)
	if err != nil {
		return false, fmt.Errorf("Unable to check envoy listener worker state because of : %s", err)
	}
	defer res.Body.Close()
	return kr.processHealthCheckResponse(res, listenerCheckKey, "1") // 1 indicates listener works have started.
}

// Checks the res has the following structure: "key: val" where key and val should be as specified.
func (kr *KRun) processHealthCheckResponse(res *http.Response, key string, val string) (bool, error) {
	if res == nil || res.StatusCode != 200 {
		return false, fmt.Errorf("Unable to check envoy for %s", key)
	}

	rawResponse, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return false, fmt.Errorf("Unable to check envoy for %s because of %s", key, err)
	}

	response := string(rawResponse)
	splits := strings.Split(response, ":")
	if len(splits) != 2 {
		return false, nil
	}

	// Check key
	if strings.TrimSpace(splits[0]) != key {
		return false, nil
	}
	// Check val
	if strings.TrimSpace(splits[1]) != val {
		return false, nil
	}
	return true, nil
}
