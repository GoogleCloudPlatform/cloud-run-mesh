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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
)

// WIP: copied from istio agent, to allow proxyless gRPC to start without a dependency to the full pilot-agent and
// without the XDS proxy. This still depends on finishing up direct integration with the CA.
// Note that gRPC does not support using custom SAN for the XDS server - MCP will work since it has real certs.
// For in-cluster you need a proper gateway with real certs exposing Istiod. The east/west gateway (hgate) can handle
// this, but with CertManager or some other tool creating the certs and with a DNS entry. A Serverless gateway can
// also provide a similar domain+certificates.

const (
	ServerListenerNamePrefix = "xds.istio.io/grpc/lds/inbound/"
	// ServerListenerNameTemplate for the name of the Listener resource to subscribe to for a gRPC
	// server. If the token `%s` is present in the string, all instances of the
	// token will be replaced with the server's listening "IP:port" (e.g.,
	// "0.0.0.0:8080", "[::]:8080").
	ServerListenerNameTemplate = ServerListenerNamePrefix + "%s"
)

// Bootstrap contains the general structure of what's expected by GRPC's XDS implementation.
// See https://github.com/grpc/grpc-go/blob/master/xds/internal/xdsclient/bootstrap/bootstrap.go
// TODO use structs from gRPC lib if created/exported
type Bootstrap struct {
	XDSServers                 []XdsServer                    `json:"xds_servers,omitempty"`
	Node                       *Node                          `json:"node,omitempty"`
	CertProviders              map[string]CertificateProvider `json:"certificate_providers,omitempty"`
	ServerListenerNameTemplate string                         `json:"server_listener_resource_name_template,omitempty"`
}

type ChannelCreds struct {
	Type   string      `json:"type,omitempty"`
	Config interface{} `json:"config,omitempty"`
}

type XdsServer struct {
	ServerURI      string         `json:"server_uri,omitempty"`
	ChannelCreds   []ChannelCreds `json:"channel_creds,omitempty"`
	ServerFeatures []string       `json:"server_features,omitempty"`
}

type CertificateProvider struct {
	PluginName string      `json:"plugin_name,omitempty"`
	Config     interface{} `json:"config,omitempty"`
}

const FileWatcherCertProviderName = "file_watcher"

type FileWatcherCertProviderConfig struct {
	CertificateFile   string          `json:"certificate_file,omitempty"`
	PrivateKeyFile    string          `json:"private_key_file,omitempty"`
	CACertificateFile string          `json:"ca_certificate_file,omitempty"`
	RefreshDuration   json.RawMessage `json:"refresh_interval,omitempty"`
}

func (c *FileWatcherCertProviderConfig) FilePaths() []string {
	return []string{c.CertificateFile, c.PrivateKeyFile, c.CACertificateFile}
}

// FileWatcherProvider returns the FileWatcherCertProviderConfig if one exists in CertProviders
func (b *Bootstrap) FileWatcherProvider() *FileWatcherCertProviderConfig {
	if b == nil || b.CertProviders == nil {
		return nil
	}
	for _, provider := range b.CertProviders {
		if provider.PluginName == FileWatcherCertProviderName {
			cfg, ok := provider.Config.(FileWatcherCertProviderConfig)
			if !ok {
				return nil
			}
			return &cfg
		}
	}
	return nil
}

// LoadBootstrap loads a Bootstrap from the given file path.
func LoadBootstrap(file string) (*Bootstrap, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	b := &Bootstrap{}
	if err := json.Unmarshal(data, b); err != nil {
		return nil, err
	}
	return b, err
}

// Duplicated from github.com/envoyproxy/go-control-plane/envoy/config/core/v3
// to avoid deps to large package. Only what we use.
type Node struct {
	Id       string           `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Locality *Locality        `protobuf:"bytes,4,opt,name=locality,proto3" json:"locality,omitempty"`
	Metadata *structpb.Struct `protobuf:"bytes,3,opt,name=metadata,proto3" json:"metadata,omitempty"`
}

type GenerateBootstrapOptions struct {
	Node             *Node
	XdsUdsPath       string
	DiscoveryAddress string
	CertDir          string
}

type Locality struct {
	// Region this :ref:`zone <envoy_api_field_config.core.v3.Locality.zone>` belongs to.
	Region string `protobuf:"bytes,1,opt,name=region,proto3" json:"region,omitempty"`
	// Defines the local service zone where Envoy is running. Though optional, it
	// should be set if discovery service routing is used and the discovery
	// service exposes :ref:`zone data <envoy_api_field_config.endpoint.v3.LocalityLbEndpoints.locality>`,
	// either in this message or via :option:`--service-zone`. The meaning of zone
	// is context dependent, e.g. `Availability Zone (AZ)
	// <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html>`_
	// on AWS, `Zone <https://cloud.google.com/compute/docs/regions-zones/>`_ on
	// GCP, etc.
	Zone string `protobuf:"bytes,2,opt,name=zone,proto3" json:"zone,omitempty"`
	// When used for locality of upstream hosts, this field further splits zone
	// into smaller chunks of sub-zones so they can be load balanced
	// independently.
	SubZone string `protobuf:"bytes,3,opt,name=sub_zone,json=subZone,proto3" json:"sub_zone,omitempty"`
}

// GenerateBootstrap generates the bootstrap structure for gRPC XDS integration.
func GenerateBootstrap(opts GenerateBootstrapOptions, meta map[string]string) (*Bootstrap, error) {
	xdsMeta, err := extractMeta(meta)
	if err != nil {
		return nil, fmt.Errorf("failed extracting xds metadata: %v", err)
	}

	// TODO direct to CP should use secure channel (most likely JWT + TLS, but possibly allow mTLS)
	serverURI := opts.DiscoveryAddress
	if opts.XdsUdsPath != "" {
		serverURI = fmt.Sprintf("unix:///%s", opts.XdsUdsPath)
	}

	bootstrap := Bootstrap{
		XDSServers: []XdsServer{{
			ServerURI: serverURI,
			// connect locally via agent
			ChannelCreds:   []ChannelCreds{{Type: "insecure"}},
			ServerFeatures: []string{"xds_v3"},
		}},
		Node: &Node{
			Id:       opts.Node.Id,
			Locality: opts.Node.Locality,
			Metadata: xdsMeta,
		},
		ServerListenerNameTemplate: ServerListenerNameTemplate,
	}

	if opts.CertDir != "" {
		// TODO use a more appropriate interval
		refresh, err := protojson.Marshal(durationpb.New(15 * time.Minute))
		if err != nil {
			return nil, err
		}

		bootstrap.CertProviders = map[string]CertificateProvider{
			"default": {
				PluginName: "file_watcher",
				Config: FileWatcherCertProviderConfig{
					PrivateKeyFile:    path.Join(opts.CertDir, "key.pem"),
					CertificateFile:   path.Join(opts.CertDir, "cert-chain.pem"),
					CACertificateFile: path.Join(opts.CertDir, "root-cert.pem"),
					RefreshDuration:   refresh,
				},
			},
		}
	}

	return &bootstrap, err
}

func extractMeta(meta map[string]string) (*structpb.Struct, error) {
	bytes, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	rawMeta := map[string]interface{}{}
	if err := json.Unmarshal(bytes, &rawMeta); err != nil {
		return nil, err
	}
	xdsMeta, err := structpb.NewStruct(rawMeta)
	if err != nil {
		return nil, err
	}
	return xdsMeta, nil
}

// GenerateBootstrapFile generates and writes atomically as JSON to the given file path.
func GenerateBootstrapFile(opts GenerateBootstrapOptions, path string) (*Bootstrap, error) {
	bootstrap, err := GenerateBootstrap(opts, nil)
	if err != nil {
		return nil, err
	}
	jsonData, err := json.MarshalIndent(bootstrap, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := ioutil.WriteFile(path, jsonData, os.FileMode(0o644)); err != nil {
		return nil, fmt.Errorf("failed writing to %s: %v", path, err)
	}
	return bootstrap, nil
}
