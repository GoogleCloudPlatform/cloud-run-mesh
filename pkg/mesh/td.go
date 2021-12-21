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
	"net"
	"os"
	"strconv"
	"strings"

	"cloud.google.com/go/compute/metadata"
	"github.com/google/uuid"
)

// TDSidecarEnv contains environment files that controls how an envoy proxy will be
// set up and interact with Traffic Director control plane.
type TdSidecarEnv struct {
	// Scope specifies the mesh in a project.
	Scope string
	// List of comma seperated IP ranges that will have their traffic intercepted
	// and redirected to Envoy. Set it to '*' to intercept all traffic.
	ServiceCidr string
	// Envoy listening port. Outbound traffic will be redirected to this port.
	EnvoyPort string
	// Envoy admin interface listening port. Admin interface will only be available on
	// localhost.
	EnvoyAdminPort string
	// Location for envoy output.
	LogDirectory string
	// Envoy log level. Must be one of [trace][debug][info][warning][error][critical][off]
	LogLevel string
	// If set to "true", enables generation of tracing for inbound and outbound.
	TracingEnabled bool
	// Port on which Envoy listener will resolve DNS requests. Outbound DNS requests
	// will be intercepted and forwarded to Envoy on this port.
	EnvoyDnsPort string
	// Zone of the current CloudRun service.
	EnvoyZone string
	// NodeId that this envoy client will use with TD control plane.
	NodeID string
	// Location of public server cert for GCP Traffic Director over HTTPS
	XdsServerCert string
	// Location of envoy template file and script associated with setting up envoy for TD support.
	PackageDirectory string
}

// NewTdSidecarEnv sets up TdSideCarEnv with defaults.
func NewTdSidecarEnv() *TdSidecarEnv {
	return &TdSidecarEnv{
		Scope:            "default",
		ServiceCidr:      "*",
		EnvoyPort:        "15001",
		EnvoyAdminPort:   "15000",
		LogDirectory:     "/var/log/envoy/",
		LogLevel:         "info",
		TracingEnabled:   false,
		EnvoyDnsPort:     "15053",
		XdsServerCert:    "/etc/ssl/certs/ca-certificates.crt",
		PackageDirectory: "/td_resources",
	}
}

// Currently zone/region is loaded for the cloud run instance using the metadata server.
func (td *TdSidecarEnv) fetchZone() (string, error) {
	zone, err := metadata.Get("instance/zone")
	if err != nil {
		return "", fmt.Errorf("could not determine zone from metadata server: %s", err)
	}
	splits := strings.SplitAfter(zone, "/zones/")
	if len(splits) != 2 {
		return "", fmt.Errorf("could not determine zone from metadata server: %s", err)
	}
	return splits[1], nil
}

func (td *TdSidecarEnv) fetchProjectNumber() (string, error) {
	projectNumber, err := metadata.Get("project/numeric-project-id")
	if err != nil {
		return "", fmt.Errorf("could not determine project number from metadata server: %s", err)
	}
	return projectNumber, nil
}

func (td *TdSidecarEnv) fetchNodeID() (string, error) {
	hostName, hostErr := os.Hostname()
	if hostErr != nil {
		return "", hostErr
	}
	ips, ipErr := net.LookupIP(hostName)
	if ipErr != nil {
		return "", ipErr
	}
	if len(ips) == 0 {
		return "", errors.New("empty IP for host when fetching TD Node Id")
	}
	return fmt.Sprintf("%s~%s", uuid.New().String(), ips[0].String()), nil
}

func (td *TdSidecarEnv) getIPTablesInterceptionEnvVars() []string {
	envs := []string{
		"TRAFFIC_DIRECTOR_GCE_VM_DEPLOYMENT_OVERRIDE=true",
		"DISABLE_REDIRECTION_ON_LOCAL_LOOPBACK=true",
		fmt.Sprintf("%s=%s", "ENVOY_DNS_PORT", td.EnvoyDnsPort),
	}
	return envs
}

func (kr *KRun) prepareTrafficDirectorBootstrap(templatePath string, outputPath string) error {
	data, err := os.ReadFile(templatePath)
	if err != nil {
		return err
	}

	template := string(data)
	template = strings.ReplaceAll(template, "ENVOY_NODE_ID", kr.TdSidecarEnv.NodeID)
	template = strings.ReplaceAll(template, "ENVOY_ZONE", kr.TdSidecarEnv.EnvoyZone)
	template = strings.ReplaceAll(template, "VPC_NETWORK_NAME", fmt.Sprintf("scope:%s", kr.TdSidecarEnv.Scope))
	template = strings.ReplaceAll(template, "CONFIG_PROJECT_NUMBER", kr.ProjectNumber)
	template = strings.ReplaceAll(template, "ENVOY_PORT", kr.TdSidecarEnv.EnvoyPort)
	template = strings.ReplaceAll(template, "ENVOY_ADMIN_PORT", kr.TdSidecarEnv.EnvoyAdminPort)
	template = strings.ReplaceAll(template, "XDS_SERVER_CERT", kr.TdSidecarEnv.XdsServerCert)
	template = strings.ReplaceAll(template, "TRACING_ENABLED", strconv.FormatBool(kr.TdSidecarEnv.TracingEnabled))
	template = strings.ReplaceAll(template, "ACCESSLOG_PATH", "")
	template = strings.ReplaceAll(template, "BACKEND_INBOUND_PORTS", "")

	if err = os.WriteFile(outputPath, []byte(template), 0666); err != nil {
		return err
	}
	return nil
}
