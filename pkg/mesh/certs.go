package mesh

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WIP - consolidate cert signing, not require pilot-agent for proxyless gRPC.
// TODO: rotation
// TODO: save last cert in the chain to roots
// TODO: only use CAS if mesh-env is configured

const (
	blockTypeECPrivateKey    = "EC PRIVATE KEY"
	blockTypeRSAPrivateKey   = "RSA PRIVATE KEY" // PKCS#1 private key
	blockTypePKCS8PrivateKey = "PRIVATE KEY"     // PKCS#8 plain private key
)

// Common setup for cert management.
// After the 'mesh-env' is loaded (from env, k8s, URL) the next step is to init the workload identity.
// This must happen before connecting to XDS - since certs is one of the possible auth methods.
//
// The logic is:
// - (best case) certificates already provisioned by platform. Detects GKE paths (CAS), old Istio, CertManager style
//   If workload certs are platform-provisioned: extract trust domain, namespace, name, pod id from cert.
//
// - Detect the WORKLOAD_SERVICE_ACCOUNT, trust domain from JWT or mesh-env
// - Use WORKLOAD_CERT json to load the config for the CSR, create a CSR
// - Call CSRSigner.
// - Save the certificates if running as root or an output dir is set. This will use CAS naming convention.
//
// If envoy + pilot-agent are used, they should be configured to use the cert files.
// This is done by setting "CA_PROVIDER=GoogleGkeWorkloadCertificate" when starting pilot-agent
func (kr *KRun) InitCertificates(ctx context.Context, outDir string) error {
	var err error
	keyFile := filepath.Join(outDir, privateKey)
	chainFile := filepath.Join(outDir, cert)
	if outDir != "" {
		kp, err := tls.LoadX509KeyPair(chainFile, keyFile)
		if err == nil && len(kp.Certificate) > 0 {
			kp.Leaf, _ = x509.ParseCertificate(kp.Certificate[0])

			exp := kp.Leaf.NotAfter.Sub(time.Now())
			if exp > -5 * time.Minute {
				kr.X509KeyPair = &kp
				log.Println("Existing Cert", "expires", exp)
				return nil
			}
		}
	}
	if kr.CSRSigner == nil {
		return nil
	}
	// TODO: decode WorkloadCertificateConfig, use EC256 or RSA
	privPEM, csr, err := kr.NewCSR("rsa", kr.TrustDomain, "spiffe://"+kr.TrustDomain+"/ns/"+kr.Namespace+"/sa/"+kr.KSA)
	if err != nil {
		return err
	}
	chain, err := kr.CSRSigner.CSRSign(ctx, csr, 24*3600)
	if err != nil {
		return err
	}
	certChain := strings.Join(chain, "\n")

	kp, err := tls.X509KeyPair([]byte(certChain), privPEM)
	kr.X509KeyPair = &kp

	if err == nil && len(kp.Certificate) > 0 {
		kp.Leaf, _ = x509.ParseCertificate(kp.Certificate[0])

		if !kp.Leaf.NotAfter.Before(time.Now()) {
			r, _ := x509.ParseCertificate(kp.Certificate[len(kp.Certificate) - 1])
			log.Println("New Cert", "expires", kp.Leaf.NotAfter, "signer", r.Subject)
		}
	}
	if outDir != "" {
		os.MkdirAll(outDir, 0755)
		err = ioutil.WriteFile(keyFile, privPEM, 0660)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(chainFile, []byte(certChain), 0660)
		if err != nil {
			return err
		}
		if os.Getuid() == 0 {
			os.Chown(outDir, 1337, 1337)
			os.Chown(keyFile, 1337, 1337)
			os.Chown(chainFile, 1337, 1337)

		}
	}
	// The roots are extracted from the mesh env.

	return err
}

// InitRoots will find the mesh roots.
//
// - if Zatar or another CSI provider are enabled, we do nothing - Zatar config is the root of trust for everything
// - otherwise the roots are expected to be part of mesh-env. The mesh connector or other tools will
//  populate it - ideally from the CSI/Zatar or TrustConfig CRD.
func (kr *KRun) InitRoots(ctx context.Context, outDir string) error {
	rootFile := filepath.Join(outDir, WorkloadRootCAs)
	if outDir != "" {
		rootCertPEM, err := ioutil.ReadFile(rootFile)
		if err == nil {
			block, rest := pem.Decode(rootCertPEM)

			var blockBytes []byte
			for block != nil {
				blockBytes = append(blockBytes, block.Bytes...)
				block, rest = pem.Decode(rest)
			}

			rootCAs, err := x509.ParseCertificates(blockBytes)
			if err != nil {
				return err
			}
			for _, c := range rootCAs {
				kr.TrustedCertPool.AddCert(c)
			}
			return nil
		}
	}

	// File not found - extract it from mesh env, and save it.
	// This includes Citadel root (if active in the mesh) or other roots.
	roots := ""
	for k, v := range kr.MeshEnv {
		if strings.HasPrefix(k, "CAROOT") {
			roots = roots + "\n" + v
		}
	}
	block, rest := pem.Decode([]byte(roots))
	var blockBytes []byte
	for block != nil {
		blockBytes = append(blockBytes, block.Bytes...)
		block, rest = pem.Decode(rest)
	}

	rootCAs, err := x509.ParseCertificates(blockBytes)
	if err != nil {
		return err
	}
	for _, c := range rootCAs {
		kr.TrustedCertPool.AddCert(c)
	}

	if outDir != "" {
		os.MkdirAll(outDir, 0660)
		err = ioutil.WriteFile(rootFile, []byte(roots), 0644)
		if err != nil {
			return err
		}
	}

	return nil
}

type CSRSigner interface {
	CSRSign(ctx context.Context, csrPEM []byte, certValidTTLInSec int64) ([]string, error)
}

const (

	WorkloadCertDir = "./var/run/secrets/workload-spiffe-credentials"

	// Different from typical Istio  and CertManager key.pem - we can check both
	privateKey = "private_key.pem"

	// Also different, we'll check all. CertManager uses cert.pem
	cert = "certificates.pem"

	// This is derived from CA certs plus all TrustAnchors.
	// In GKE, it is expected that Citadel roots will be configure using TrustConfig - so they are visible
	// to all workloads including TD proxyless GRPC.
	//
	// Outside of GKE, this is loaded from the mesh.env - the mesh gate is responsible to keep it up to date.
	WorkloadRootCAs = "ca_certificates.pem"
)

type WorkloadCertificateConfigSpec struct {
	CertificateAuthorityConfig CertificateAuthorityConfig `json:"certificateAuthorityConfig"`
	ValidityDurationSeconds    int64                      `json:"validityDurationSeconds,omitempty"`
	RotationWindowPercentage   int64                      `json:"rotationWindowPercentage,omitempty"`
	KeyAlgorithm               *KeyAlgorithm              `json:"keyAlgorithm,omitempty"`
}

type CertificateAuthorityConfig struct {
	MeshCAConfig                      *MeshCAConfig                      `json:"meshCAConfig,omitempty"`
	CertificateAuthorityServiceConfig *CertificateAuthorityServiceConfig `json:"certificateAuthorityServiceConfig,omitempty"`
}

type MeshCAConfig struct {
}

type CertificateAuthorityServiceConfig struct {
	// Format: //privateca.googleapis.com/projects/PROJECT_ID/locations/SUBORDINATE_CA_LOCATION/caPools/SUBORDINATE_CA_POOL_NAME
	EndpointURI string `json:"endpointURI"`
}

type KeyAlgorithm struct {
	RSA   *RSA   `json:"rsa,omitempty"`
	ECDSA *ECDSA `json:"ecdsa,omitempty"`
}

type RSA struct {
	ModulusSize int `json:"modulusSize"`
}

type ECDSA struct {
	Curve string `json:"curve"`
}



// TrustConfig is the GKE config - when used outside GKE this is passed in the mesh-env
type TrustConfigSpec struct {
	TrustStores []TrustStore `json:"trustStores"`
}

type TrustStore struct {
	TrustDomain  string        `json:"trustDomain"`
	TrustAnchors []TrustAnchor `json:"trustAnchors,omitempty"`
}

type TrustAnchor struct {
	SPIFFETrustBundleEndpoint      string `json:"spiffeTrustBundleEndpoint,omitempty"`

	// Format: //privateca.googleapis.com/projects/PROJECT_ID/locations/ROOT_CA_POOL_LOCATION/caPools/ROOT_CA_POOL_NAME
	CertificateAuthorityServiceURI string `json:"certificateAuthorityServiceURI,omitempty"`

	PEMCertificate                 string `json:"pemCertificate,omitempty"`
}




func CheckFiles() {

}

//
//
func SaveFiles() {

}

func (a *KRun) NewCSR(kty string, trustDomain, san string) (privPEM []byte, csrPEM []byte, err error) {
	var priv crypto.PrivateKey

	if kty == "ec256" {
		// TODO
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	priv = rsaKey

	csr := GenCSRTemplate(trustDomain, san)
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, priv)

	encodeMsg := "CERTIFICATE REQUEST"

	csrPEM = pem.EncodeToMemory(&pem.Block{Type: encodeMsg, Bytes: csrBytes})

	var encodedKey []byte
	//if pkcs8 {
	//	if encodedKey, err = x509.MarshalPKCS8PrivateKey(priv); err != nil {
	//		return nil, nil, err
	//	}
	//	privPem = pem.EncodeToMemory(&pem.Block{Type: blockTypePKCS8PrivateKey, Bytes: encodedKey})
	//} else {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		encodedKey = x509.MarshalPKCS1PrivateKey(k)
		privPEM = pem.EncodeToMemory(&pem.Block{Type: blockTypeRSAPrivateKey, Bytes: encodedKey})
	case *ecdsa.PrivateKey:
		encodedKey, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, nil, err
		}
		privPEM = pem.EncodeToMemory(&pem.Block{Type: blockTypeECPrivateKey, Bytes: encodedKey})
	}
	//}

	return
}

func GenCSRTemplate(trustDomain, san string) *x509.CertificateRequest {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{trustDomain},
		},
	}

	// TODO: add the SAN, it is not required, server will fill up

	return template
}
