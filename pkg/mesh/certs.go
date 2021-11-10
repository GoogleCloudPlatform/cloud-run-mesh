package mesh

import "context"

// Common file for cert management

type CertProvider interface {
	CSRSign(ctx context.Context, csrPEM []byte, certValidTTLInSec int64) ([]string, error)
	GetRootCertBundle(ctx context.Context)
}

const (

	certBase = "./var/run/secrets/workload-spiffe-credentials"

	// Different from typical Istio  and CertManager key.pem - we can check both
	privateKey = "private_key.pem"

	// Also different, we'll check all. CertManager uses cert.pem
	cert = "certificates.pem"

	// This is derived from CA certs plus all TrustAnchors.
	// In GKE, it is expected that Citadel roots will be configure using TrustConfig - so they are visible
	// to all workloads including TD proxyless GRPC.
	//
	// Outside of GKE, this is loaded from the mesh.env - the mesh gate is responsible to keep it up to date.
	rootCA = "ca_certificates.pem"
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
