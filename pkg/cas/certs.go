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

package cas

import (
	"fmt"
	"time"

	"context"
	"log"

	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	"k8s.io/apimachinery/pkg/util/rand"

	privateca "cloud.google.com/go/security/privateca/apiv1"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1"
)

type casCertProvider struct {
	capool   string
	caClient *privateca.CertificateAuthorityClient
}




// NewCASCertProvider create a client for Google CAS.
//
// capool is in format: projects/*/locations/*/caPools/*
//
// Should default based on the config project and the location of the config cluster.
//
// Files: if running as root, will create the well-known files:
// -
//
// In GKE, if "--enable-mesh-certificates" cluster option and and the annotation
//  "security.cloud.google.com/use-workload-certificates" will automatically
// create the files and this is not needed. As such the file should be checked first.
// The config in GKE is based on WorkloadCertificateConfig - this file is attempting to emulate it.
//
//
// See: https://cloud.google.com/traffic-director/docs/security-proxyless-setup?hl=en
func NewCASCertProvider(capool string, ol []grpc.DialOption) (*casCertProvider, error) {
	caClient := &casCertProvider{capool: capool}
	ctx := context.Background()
	var err error

	var ol1  []option.ClientOption
	for _, v := range ol {
		ol1 = append(ol1, option.WithGRPCDialOption(v))
	}
	caClient.caClient, err = privateca.NewCertificateAuthorityClient(ctx, ol1...)

	if err != nil {
		log.Printf("unable to initialize google cas caclient: %v", err)
		return nil, err
	}
	return caClient, nil
}

func (r *casCertProvider) createCertReq(csrPEM []byte, lifetime time.Duration) *privatecapb.CreateCertificateRequest {
	var isCA bool = false

	rand.Seed(time.Now().UnixNano())
	name := fmt.Sprintf("csr-workload-%s", rand.String(8))

	// We use Certificate_Config option to ensure that we only request a certificate with CAS supported extensions/usages.
	// CAS uses the PEM encoded CSR only for its public key and infers the certificate SAN (identity) of the workload through SPIFFE identity reflection
	creq := &privatecapb.CreateCertificateRequest{
		Parent:        r.capool,
		CertificateId: name,
		Certificate: &privatecapb.Certificate{
			Lifetime: durationpb.New(lifetime),
			CertificateConfig: &privatecapb.Certificate_Config{
				Config: &privatecapb.CertificateConfig{
					SubjectConfig: &privatecapb.CertificateConfig_SubjectConfig{
						Subject: &privatecapb.Subject{},
					},
					X509Config: &privatecapb.X509Parameters{
						KeyUsage: &privatecapb.KeyUsage{
							BaseKeyUsage: &privatecapb.KeyUsage_KeyUsageOptions{
								DigitalSignature: true,
								KeyEncipherment:  true,
							},
							ExtendedKeyUsage: &privatecapb.KeyUsage_ExtendedKeyUsageOptions{
								ServerAuth: true,
								ClientAuth: true,
							},
						},
						CaOptions: &privatecapb.X509Parameters_CaOptions{
							IsCa: &isCA,
						},
					},
					PublicKey: &privatecapb.PublicKey{
						Format: privatecapb.PublicKey_PEM,
						Key:    csrPEM,
					},
				},
			},
			SubjectMode: privatecapb.SubjectRequestMode_REFLECTED_SPIFFE,
		},
	}
	return creq
}

// CSRSign returns the cert and the full path to the root. Istio workloads present full chains.
func (r *casCertProvider) CSRSign(ctx context.Context, csrPEM []byte, certValidTTLInSec int64) ([]string, error) {
	certChain := []string{}

	creq := r.createCertReq(csrPEM, time.Duration(certValidTTLInSec)*time.Second)

	cresp, err := r.caClient.CreateCertificate(ctx, creq)
	if err != nil {
		return certChain, err
	}
	certChain = append(certChain, cresp.GetPemCertificate())
	certChain = append(certChain, cresp.GetPemCertificateChain()...)
	return certChain, nil
}
