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
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"github.com/creack/pty"
)

const envoyUID = 1337
const envoyGID = 1337

func (kr *KRun) envoyCommand() *exec.Cmd {
	// For Istio:
	// -c etc/istio/proxy/envoy-rev0.json --restart-epoch 0 --drain-time-s 45 --drain-strategy immediate --parent-shutdown-time-s 60 --local-address-ip-version v4 --file-flush-interval-msec 1000 --disable-hot-restart --log-format %Y-%m-%dT%T.%fZ  %l      envoy %n        %v -l warning --component-log-level misc:error --concurrency 2
	if kr.TdSidecarEnv == nil {
		// TODO: add a simplified template, customize from ProxyConfig.
		// ProxyConfig needs to be loaded
		return exec.Command("/usr/local/bin/envoy",
			"--config-path", "etc/istio/proxy/envoy-rev0.json",
			"--allow-unknown-static-fields",
			"--restart-epoch", "0",
			"--drain-time-s", "45",
			"--drain-strategy", "immediate",
			"--parent-shutdown-time-s", "60",
			"--local-address-ip-version", "v4",
			"--file-flush-interval-msec", "1000",
			"--disable-hot-restart",
			"--log-format", "%Y-%m-%dT%T.%fZ  %l      envoy %n        %v -l warning",
			"--component-log-level", "misc:error",
			"--concurrency", "2",
		)
	}
	// For TD:
	return exec.Command("/usr/local/bin/envoy",
		"--config-path", fmt.Sprintf("%s/bootstrap.yaml", kr.TdSidecarEnv.PackageDirectory),
		"--log-level", kr.TdSidecarEnv.LogLevel,
		// Settings this will make the logs invisible and may run out of mem:
		// "--log-path", "/var/log/envoy/envoy.log",
		"--allow-unknown-static-fields",
	)
}

// StartEnvoy does iptables interception, envoy bootstrap preparation and
// runs envoy.
func (kr *KRun) StartEnvoy() error {
	if os.Getuid() != 0 {
		return errors.New("td only supports running as root")
	}

	// Prepare envoy bootstrap
	if err := kr.PrepareTrafficDirectorBootstrap(
		fmt.Sprintf("%s/bootstrap_template.yaml", kr.TdSidecarEnv.PackageDirectory),
		fmt.Sprintf("%s/bootstrap.yaml", kr.TdSidecarEnv.PackageDirectory)); err != nil {
		return err
	}
	log.Println("TD bootstrap ready")
	os.MkdirAll(kr.TdSidecarEnv.LogDirectory, 0666)
	os.Chown(kr.TdSidecarEnv.LogDirectory, envoyUID, envoyGID)

	cmd := kr.envoyCommand()

	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.SysProcAttr.Credential = &syscall.Credential{
		Uid: envoyUID,
		Gid: envoyGID,
	}

	var stdout io.ReadCloser
	pty, tty, err := pty.Open()
	if err != nil {
		log.Println("Error opening pty: ", err)
		stdout, _ = cmd.StdoutPipe()
		os.Stdout.Chown(envoyUID, envoyGID)
	} else {
		cmd.Stdout = tty
		if err = tty.Chown(envoyUID, envoyGID); err != nil {
			log.Println("Error chown: ", err)
		}
		stdout = pty
	}
	cmd.Stderr = os.Stderr

	go func() {
		if err := cmd.Start(); err != nil {
			log.Println("Failed to start: ", cmd, err)
		}
		kr.agentCmd = cmd
		if stdout != nil {
			go func() {
				io.Copy(os.Stdout, stdout)
			}()
		}
		if err := cmd.Wait(); err != nil {
			log.Println("Wait err: ", err)
		}
		kr.Exit(0)
	}()
	return nil
}

func (kr *KRun) iptablesCommand() *exec.Cmd {
	if err := os.Chmod(fmt.Sprintf("%s/iptables.sh", kr.TdSidecarEnv.PackageDirectory), 0700); err != nil {
		log.Println(err)
	}
	if err := os.Chown(fmt.Sprintf("%s/iptables.sh", kr.TdSidecarEnv.PackageDirectory), 0, 0); err != nil {
		log.Println(err)
	}
	return exec.Command(fmt.Sprintf("%s/iptables.sh", kr.TdSidecarEnv.PackageDirectory),
		"-x", "169.254.169.254/32", // metadata_server_cidr
		"-i", kr.TdSidecarEnv.ServiceCidr,
		"-p", kr.TdSidecarEnv.EnvoyPort,
		"-u", strconv.Itoa(envoyUID),
	)
}

// StartIPTablesInterception intercepts traffic via iptables script.
func (kr *KRun) StartIPTablesInterception() error {
	cmd := kr.iptablesCommand()
	so := &bytes.Buffer{}
	cmd.Dir = "/"
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, kr.GetTrafficDirectorIPTablesEnvVars()...)
	cmd.Stdout = so
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.SysProcAttr.Credential = &syscall.Credential{
		Uid: 0,
	}
	if err := cmd.Start(); err != nil {
		log.Println("Error starting iptables", err)
		return err
	}
	if err := cmd.Wait(); err != nil {
		log.Println("Error starting iptables", err, so.String())
		return err
	}
	return nil
}
