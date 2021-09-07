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

package meshca

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log"

	"github.com/golang/protobuf/ptypes/duration"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

type GoogleCAClient struct {
	caEndpoint string
	client     MeshCertificateServiceClient
	conn       *grpc.ClientConn
	Location string
}

// NewGoogleCAClient create a CA client for Google CA.
func NewGoogleCAClient(endpoint string, tokenProvider credentials.PerRPCCredentials) (*GoogleCAClient, error) {
	if endpoint == "" {
		endpoint = "meshca.googleapis.com:443"
	}
	c := &GoogleCAClient{
		caEndpoint: endpoint,
	}

	var opts grpc.DialOption
	var err error
	opts, err = c.getTLSDialOption()
	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial(endpoint,
		opts,
		grpc.WithPerRPCCredentials(tokenProvider),
		//security.CARetryInterceptor(),
	)
	if err != nil {
		log.Printf("Failed to connect to endpoint %s: %v", endpoint, err)
		return nil, fmt.Errorf("failed to connect to endpoint %s", endpoint)
	}

	c.conn = conn
	c.client = NewMeshCertificateServiceClient(conn)
	return c, nil
}

// CSR Sign calls Google CA to sign a CSR.
func (cl *GoogleCAClient) CSRSign(csrPEM []byte, certValidTTLInSec int64) ([]string, error) {
	req := &MeshCertificateRequest{
		RequestId: uuid.New().String(),
		Csr:       string(csrPEM),
		Validity:  &duration.Duration{Seconds: certValidTTLInSec},
	}

	out := metadata.New(nil)
	if cl.Location != "" {
		out["x-goog-request-params"] = []string{fmt.Sprintf("location=locations/%s", cl.Location)}
	}

	ctx := metadata.NewOutgoingContext(context.Background(), out)
	resp, err := cl.client.CreateCertificate(ctx, req)
	if err != nil {
		log.Printf("Failed to create certificate: %v", err)
		return nil, err
	}

	if len(resp.CertChain) <= 1 {
		log.Printf("CertChain length is %d, expected more than 1", len(resp.CertChain))
		return nil, errors.New("invalid response cert chain")
	}

	return resp.CertChain, nil
}

func (cl *GoogleCAClient) Close() {
	if cl.conn != nil {
		cl.conn.Close()
	}
}

func (cl *GoogleCAClient) getTLSDialOption() (grpc.DialOption, error) {
	// Load the system default root certificates.
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.New("could not get SystemCertPool")
	}
	creds := credentials.NewClientTLSFromCert(pool, "")
	return grpc.WithTransportCredentials(creds), nil
}
