package proxy

import (
	"container/list"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CA represents a certificate authority for TLS interception.
// The key field is a crypto.Signer so both RSA and EC CA keys are supported.
type CA struct {
	cert    *x509.Certificate
	key     crypto.Signer
	certPEM []byte
	keyPEM  []byte

	certCache    map[string]*list.Element
	certLRU      *list.List
	cacheMu      sync.Mutex
	certCacheMax int
}

type certCacheEntry struct {
	host string
	cert *tls.Certificate
}

// defaultCertCacheMax bounds cached leaf certificates so a client sending
// CONNECT to many hostnames cannot grow memory without limit.
const defaultCertCacheMax = 1024

const (
	defaultCAOrganization = "Gatekeeper"
	defaultCACommonName   = "Gatekeeper CA"
)

// NewCA creates or loads a CA certificate.
// If the CA files exist at the given path, they are loaded.
// Otherwise, a new CA is generated and saved.
func NewCA(caDir string) (*CA, error) {
	return NewCAWithSubject(caDir, defaultCAOrganization, defaultCACommonName)
}

// NewCAWithSubject is NewCA with the subject of a newly generated CA set to
// the given organization and common name. A CA loaded from caDir keeps the
// subject it was created with.
func NewCAWithSubject(caDir, organization, commonName string) (*CA, error) {
	certPath := filepath.Join(caDir, "ca.crt")
	keyPath := filepath.Join(caDir, "ca.key")

	// Try to load existing CA
	if certPEM, err := os.ReadFile(certPath); err == nil {
		if keyPEM, err := os.ReadFile(keyPath); err == nil {
			return LoadCA(certPEM, keyPEM)
		}
	}

	// Generate new CA
	ca, err := generateCASubject(organization, commonName)
	if err != nil {
		return nil, err
	}

	// Save CA files
	if err := os.MkdirAll(caDir, 0700); err != nil {
		return nil, fmt.Errorf("creating CA directory: %w", err)
	}
	if err := os.WriteFile(certPath, ca.certPEM, 0644); err != nil {
		return nil, fmt.Errorf("writing CA cert: %w", err)
	}
	if err := os.WriteFile(keyPath, ca.keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("writing CA key: %w", err)
	}

	return ca, nil
}

// LoadCA loads a CA from PEM-encoded certificate and key bytes.
// Supports RSA (PKCS1, PKCS8) and EC (PKCS8, EC PRIVATE KEY) key formats.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}

	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA key PEM")
	}
	key, err := parsePrivateKey(block)
	if err != nil {
		return nil, fmt.Errorf("parsing CA key: %w", err)
	}

	return &CA{
		cert:      cert,
		key:       key,
		certPEM:   certPEM,
		keyPEM:    keyPEM,
		certCache: make(map[string]*list.Element),
		certLRU:   list.New(),
	}, nil
}

// parsePrivateKey tries multiple key formats: PKCS1 (RSA), PKCS8 (RSA/EC/Ed25519),
// and SEC 1 (EC). Returns a crypto.Signer or an error.
func parsePrivateKey(block *pem.Block) (crypto.Signer, error) {
	// Try PKCS8 first — handles RSA, EC, and Ed25519 keys.
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
		return nil, fmt.Errorf("PKCS8 key does not implement crypto.Signer")
	}

	// Try PKCS1 (RSA only).
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try SEC 1 / EC private key.
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("unsupported key format (tried PKCS8, PKCS1, EC)")
}

// generateCA creates a new CA certificate and key.
func generateCA() (*CA, error) {
	return generateCASubject(defaultCAOrganization, defaultCACommonName)
}

func generateCASubject(organization, commonName string) (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating CA key: %w", err)
	}

	// Generate subject key identifier
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling public key: %w", err)
	}
	subjectKeyID := sha1.Sum(pubKeyBytes)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{organization},
			CommonName:   commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          subjectKeyID[:],
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing generated certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return &CA{
		cert:      cert,
		key:       key,
		certPEM:   certPEM,
		keyPEM:    keyPEM,
		certCache: make(map[string]*list.Element),
		certLRU:   list.New(),
	}, nil
}

// CertPEM returns the CA certificate in PEM format.
func (ca *CA) CertPEM() []byte {
	return ca.certPEM
}

// GenerateCert creates a certificate for the given host signed by the CA.
func (ca *CA) GenerateCert(host string) (*tls.Certificate, error) {
	// Check cache first
	ca.cacheMu.Lock()
	if el, ok := ca.certCache[host]; ok {
		ca.certLRU.MoveToFront(el)
		cert := el.Value.(*certCacheEntry).cert
		ca.cacheMu.Unlock()
		return cert, nil
	}
	ca.cacheMu.Unlock()

	// Generate new certificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: ca.cert.Subject.Organization,
			CommonName:   host,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0), // 1 year
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Add host as SAN
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("creating certificate: %w", err)
	}

	// Include CA cert in chain so clients can verify the full chain.
	// Some SSL libraries (like Python's) need the issuer cert in the chain
	// even when using a custom CA bundle.
	cert := &tls.Certificate{
		Certificate: [][]byte{certDER, ca.cert.Raw},
		PrivateKey:  key,
	}

	// Cache the certificate
	ca.cacheMu.Lock()
	if el, ok := ca.certCache[host]; ok {
		el.Value.(*certCacheEntry).cert = cert
		ca.certLRU.MoveToFront(el)
	} else {
		ca.certCache[host] = ca.certLRU.PushFront(&certCacheEntry{host: host, cert: cert})
	}
	limit := ca.certCacheMax
	if limit <= 0 {
		limit = defaultCertCacheMax
	}
	for ca.certLRU.Len() > limit {
		oldest := ca.certLRU.Back()
		ca.certLRU.Remove(oldest)
		delete(ca.certCache, oldest.Value.(*certCacheEntry).host)
	}
	ca.cacheMu.Unlock()

	return cert, nil
}
