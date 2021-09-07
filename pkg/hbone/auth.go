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

package hbone

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	blockTypeECPrivateKey    = "EC PRIVATE KEY"
	blockTypeRSAPrivateKey   = "RSA PRIVATE KEY" // PKCS#1 private key
	blockTypePKCS8PrivateKey = "PRIVATE KEY"     // PKCS#8 plain private key
)

type Auth struct {
	// Will attempt to load certificates from this directory, defaults to
	// "./var/run/secrets/istio.io/"
	CertDir   string

	// Current certificate, after calling GetCertificate("")
	Cert          *tls.Certificate

	// MeshTLSConfig is a tls.Config that requires mTLS with a spiffee identity,
	// using the configured roots, trustdomains.
	//
	// By default only same namespace or istio-system are allowed - can be changed by
	// setting AllowedNamespaces. A "*" will allow all.
	MeshTLSConfig *tls.Config

	// TrustDomain is extracted from the cert or set by user, used to verify
	// peer certificates.
	TrustDomain string

	// Namespace and SA are extracted from the certificate or set by user.
	// Namespace is used to verify peer certificates
	Namespace   string
	SA          string

	AllowedNamespaces []string

	// Trusted roots
	// TODO: copy Istiod multiple trust domains code. This will be a map[trustDomain]roots and a
	// list of TrustDomains. XDS will return the info via ProxyConfig.
	// This can also be done by krun - loading a config map with same info.
	TrustedCertPool *x509.CertPool

	GetCertificateHook func(host string) (*tls.Certificate, error)
}

// NewAuthFromDir will load the credentials and create an Auth object.
//
// This uses pilot-agent or some other platform tool creating ./var/run/secrets/istio.io/{key,cert-chain}.pem
//
//
// TODO: ./etc/certs support: krun should copy the files, for consistency (simper code for frameworks).
// TODO: periodic reload
func NewAuthFromDir(dir string) (*Auth, error){
	a := NewAuth()
	a.CertDir = dir
	err := a.waitAndInitFromDir()
	if err != nil {
		return nil, err
	}
	return a, nil
}

func NewAuth() (*Auth){
	a := &Auth{
		TrustedCertPool: x509.NewCertPool(),
	}
	return a
}

func (a *Auth) SetKeysPEM(privatePEM []byte, chainPEM []string) error {
	chainPEMCat := strings.Join(chainPEM, "\n")
	tlsCert, err := tls.X509KeyPair([]byte(chainPEMCat), privatePEM)
	if err != nil {
		return err
	}
	a.Cert = &tlsCert
	if tlsCert.Certificate == nil || len(tlsCert.Certificate) == 0 {
		return errors.New("missing certificate")
	}

	a.initTLS()
	return nil
}
func (a *Auth) leaf() *x509.Certificate {
	if a.Cert == nil {
		return nil
	}
	if a.Cert.Leaf == nil {
		a.Cert.Leaf, _ = x509.ParseCertificate(a.Cert.Certificate[0])
	}
	return a.Cert.Leaf
}

func (a *Auth) GetCertificate(host string) (*tls.Certificate, error) {
	// TODO: if host != "", allow returning DNS certs for the host.
	// Default (and currently only impl) is to return the spiffe cert
	// May refresh.

	// Have cert, not expired
	if a.Cert != nil {
		if !a.leaf().NotAfter.Before(time.Now()) {
			return a.Cert, nil
		}
	}

	if a.CertDir != "" {
		c, err := a.loadCertFromDir(a.CertDir)
		if err == nil {
			if !c.Leaf.NotAfter.Before(time.Now()) {
				a.Cert = c
			}
		} else {
			log.Println("Cert from dir failed", err)
		}
	}

	if a.GetCertificateHook != nil {
		c, err := a.GetCertificateHook(host)
		if err != nil {
			return nil, err
		}
		a.Cert = c
	}

	return a.Cert, nil
}

func (a *Auth) loadCertFromDir(dir string) (*tls.Certificate, error) {
	// Load cert from file
	keyFile := filepath.Join(dir, "key.pem")
	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	certBytes, err := ioutil.ReadFile(filepath.Join(dir, "cert-chain.pem"))
	if err != nil {
		return nil, err
	}

	tlsCert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, err
	}
	if tlsCert.Certificate == nil || len(tlsCert.Certificate) == 0 {
		return nil, errors.New("missing certificate")
	}
	tlsCert.Leaf, _ = x509.ParseCertificate(tlsCert.Certificate[0])

	return &tlsCert, nil
}

func (a *Auth) waitAndInitFromDir() error {
	if a.CertDir == "" {
		a.CertDir = "./var/run/secrets/istio.io/"
	}
	keyFile := filepath.Join(a.CertDir, "key.pem")
	err := WaitFile(keyFile, 5*time.Second)
	if err != nil {
		return err
	}
	if a.Cert == nil {
		_, err := a.GetCertificate("")
		if err != nil {
			return err
		}
	}

	rootCert, _ := ioutil.ReadFile(filepath.Join(a.CertDir, "root-cert.pem"))
	if rootCert != nil {
		err2 := a.AddRoots(rootCert)
		if err2 != nil {
			return err2
		}
	}

	istioCert, _ := ioutil.ReadFile("./var/run/secrets/istio/root-cert.pem")
	if istioCert != nil {
		err2 := a.AddRoots(istioCert)
		if err2 != nil {
			return err2
		}
	}

	// Similar with /etc/ssl/certs/ca-certificates.crt - the concatenated list of PEM certs.
	rootCertExtra, _ := ioutil.ReadFile(filepath.Join(a.CertDir, "ca-certificates.crt"))
	if rootCertExtra != nil {
		err2 := a.AddRoots(rootCertExtra)
		if err2 != nil {
			return err2
		}
	}
	// If the certificate has a chain, use the last cert - similar with Istio
	if len(a.Cert.Certificate) > 1 {
		last := a.Cert.Certificate[len(a.Cert.Certificate)-1]

		rootCAs, err := x509.ParseCertificates(last)
		if err == nil {
			for _, c := range rootCAs {
				log.Println("Adding root CA from cert chain: ", c.Subject)
				a.TrustedCertPool.AddCert(c)
			}
		}
	}

	a.initTLS()
	return nil
}

func (a *Auth) Spiffee() (*url.URL, string, string, string) {
	cert, err := x509.ParseCertificate(a.Cert.Certificate[0])
	if err != nil {
		return nil, "","",""
	}
	if len(cert.URIs) > 0 {
		c0 := cert.URIs[0]
		pathComponetns := strings.Split(c0.Path, "/")
		if c0.Scheme == "spiffe" && pathComponetns[1] == "ns" && pathComponetns[3] == "sa" {
			return c0, c0.Host, pathComponetns[2], pathComponetns[4]
		}
	}
	return nil,"","",""
}

func (a *Auth) ID() string {
	su, _, _, _ := a.Spiffee()
	return su.String()
}

func (a *Auth) setSpiffe()  {
	_, a.TrustDomain, a.Namespace, a.SA = a.Spiffee()
}

func (a *Auth) String() string {
	cert, err := x509.ParseCertificate(a.Cert.Certificate[0])
	if err != nil {
		return ""
	}
	id := ""
	if len(cert.URIs) > 0 {
		id = cert.URIs[0].String()
	}
	return fmt.Sprintf("ID=%s,iss=%s,exp=%v,org=%s", id, cert.Issuer,
		cert.NotAfter, cert.Subject.Organization)
}

func (a *Auth) NewCSR(kty string, trustDomain, san string) (privPEM []byte, csrPEM []byte, err error) {
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

func GenCSRTemplate(trustDomain, san string) (*x509.CertificateRequest) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{trustDomain},
		},
	}

	// TODO: add the SAN, it is not required, server will fill up

	return template
}

func (a *Auth) AddRoots(rootCertPEM []byte) error {
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
		log.Println("Adding root CA: ", c.Subject)
		a.TrustedCertPool.AddCert(c)
	}
	return nil
}

func (a *Auth) initTLS() {
	a.setSpiffe()
	a.MeshTLSConfig = &tls.Config{
		//MinVersion: tls.VersionTLS13,
		//PreferServerCipherSuites: ugate.preferServerCipherSuites(),
		InsecureSkipVerify: true,                  // This is not insecure here. We will verify the cert chain ourselves.
		ClientAuth:         tls.RequestClientCert, // not require - we'll fallback to JWT

		GetCertificate: func(ch *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return a.GetCertificate(ch.ServerName)
		},

		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return a.GetCertificate("")
		},

		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				log.Println("MTLS: missing client cert")
				return errors.New("client certificate required")
			}
			var peerCert *x509.Certificate
			intCertPool := x509.NewCertPool()

			for id, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return err
				}
				if id == 0 {
					peerCert = cert
				} else {
					intCertPool.AddCert(cert)
				}
			}
			if peerCert == nil || len(peerCert.URIs) == 0 {
				log.Println("MTLS: missing URIs in Istio cert", peerCert)
				return errors.New("peer certificate does not contain URI type SAN")
			}
			c0 := peerCert.URIs[0]
			trustDomain := c0.Host
			if trustDomain != a.TrustDomain {
				log.Println("MTLS: invalid trust domain", trustDomain, peerCert.URIs)
				return errors.New("invalid trust domain " + trustDomain + " " + a.TrustDomain)
			}

			_, err := peerCert.Verify(x509.VerifyOptions{
				Roots:         a.TrustedCertPool,
				Intermediates: intCertPool,
			})
			if err != nil {
				return err
			}

			parts := strings.Split(c0.Path, "/")
			if len(parts) < 4 {
				log.Println("MTLS: invalid path", peerCert.URIs)
				return errors.New("invalid path " + c0.String())
			}

			ns := parts[2]
			if ns == "istio-system" || ns == a.Namespace {
				return nil
			}

			// TODO: also validate namespace is same with this workload or in list of namespaces ?
			if len(a.AllowedNamespaces) == 0 {
				log.Println("MTLS: namespace not allowed", peerCert.URIs)
				return errors.New("Namespace not allowed")
			}

			if a.AllowedNamespaces[0] == "*" {
				return nil
			}

			for _, ans := range a.AllowedNamespaces {
				if ns == ans {
					return nil
				}
			}

			log.Println("MTLS: namespace not allowed", peerCert.URIs)
			return errors.New("Namespace not allowed")
		},
		NextProtos: []string{"istio", "h2"},

	}
}

// WaitFile will check for the file to show up - the agent is running in a separate process.
func WaitFile(keyFile string, d time.Duration) error {
	t0 := time.Now()
	var err error
	for {
		// Wait for key file to show up - pilot agent creates it.
		if _, err := os.Stat(keyFile); os.IsNotExist(err) {
			if time.Since(t0) > d {
				return err
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		return nil
	}

	return err
}

func PublicKey(key crypto.PrivateKey) crypto.PublicKey {
	//if k, ok := key.(ed25519.PrivateKey); ok {
	//	return k.Public()
	//}
	if k, ok := key.(*ecdsa.PrivateKey); ok {
		return k.Public()
	}
	if k, ok := key.(*rsa.PrivateKey); ok {
		return k.Public()
	}

	return nil
}


// SignCertDER uses caPrivate to sign a cert, returns the DER format.
// Used primarily for tests with self-signed cert.
func SignCertDER(template *x509.Certificate, pub crypto.PublicKey, caPrivate crypto.PrivateKey, parent *x509.Certificate) ([]byte, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, caPrivate)
	if err != nil {
		return nil, err
	}
	return certDER, nil
}

func CertTemplate(org string, sans ...string) *x509.Certificate {
	var notBefore time.Time
	notBefore = time.Now().Add(-1 * time.Hour)

	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   sans[0],
			Organization: []string{org},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              sans,
		//IPAddresses:           []net.IP{auth.VIP6},
	}
	for _, k := range sans {
		if strings.Contains(k, "://") {
			u, _ := url.Parse(k)
			template.URIs = append(template.URIs, u)
		} else {
			template.DNSNames = append(template.DNSNames, k)
		}
	}
	// IPFS:
	//certKeyPub, err := x509.MarshalPKIXPublicKey(certKey.Public())
	//signature, err := sk.Sign(append([]byte(certificatePrefix), certKeyPub...))
	//value, err := asn1.Marshal(signedKey{
	//	PubKey:    keyBytes,
	//	Signature: signature,
	//})
	return &template
}

// CA is used as an internal CA, mainly for testing.
type CA struct {
	ca          *rsa.PrivateKey
	CACert      *x509.Certificate
	TrustDomain string
	prefix      string
}

func NewCA(trust string) *CA {
	ca, _ := rsa.GenerateKey(rand.Reader, 2048)
	caCert, _ := rootCert(trust, "rootCA",	ca, ca)
	return &CA{ca: ca, CACert: caCert, TrustDomain: trust,
		prefix: "spiffe://" + trust + "/ns/",
	}
}

func (ca *CA) NewID(ns, sa string) *Auth {
	nodeID := &Auth{
		TrustDomain: ca.TrustDomain,
		Namespace: ns,
		SA: sa,
	}
	caCert := ca.CACert
	nodeID.Cert = ca.NewTLSCert(ns, sa)

	nodeID.TrustedCertPool = x509.NewCertPool()
	nodeID.TrustedCertPool.AddCert(caCert)
	nodeID.initTLS()

	return nodeID
}

func (ca *CA) NewTLSCert(ns, sa string) *tls.Certificate {
	nodeKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	csr := CertTemplate(ca.TrustDomain, ca.prefix  + ns + "/sa/" + sa)
	cert, _, _ := newTLSCertAndKey(csr, nodeKey, ca.ca, ca.CACert)
	return cert
}

func newTLSCertAndKey(template *x509.Certificate, priv crypto.PrivateKey, ca crypto.PrivateKey, parent *x509.Certificate) (*tls.Certificate, []byte, []byte) {
	pub := PublicKey(priv)
	certDER, err := SignCertDER(template, pub, ca, parent)
	if err != nil {
		return nil, nil, nil
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	ecb, _ := x509.MarshalPKCS8PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecb})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, nil
	}
	return &tlsCert, keyPEM, certPEM
}

func rootCert(org, cn string, priv crypto.PrivateKey, ca crypto.PrivateKey) (*x509.Certificate, []byte) {
	pub := PublicKey(priv)
	var notBefore time.Time
	notBefore = time.Now().Add(-1 * time.Hour)

	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{org},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		IsCA: true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, ca)
	if err != nil {
		panic(err)
	}
	rootCA, _ := x509.ParseCertificates(certDER)
	return rootCA[0], certDER
}

