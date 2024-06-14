package certstore

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

var leafLifetime = 5 * time.Minute

type Store struct {
	Root *x509.Certificate
	Key  *ecdsa.PrivateKey
}

func New(key *ecdsa.PrivateKey) (*Store, error) {
	cert, err := newRootCert(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create root cert: %w", err)
	}

	return &Store{
		Root: cert,
		Key:  key,
	}, nil
}

func (s *Store) IssueLeaf(csr []byte) (*x509.Certificate, error) {
	template, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	tbs := x509.Certificate{
		SerialNumber:       big.NewInt(2),
		Subject:            template.Subject,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(leafLifetime),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		PublicKey:          template.PublicKey,
		PublicKeyAlgorithm: template.PublicKeyAlgorithm,
		Signature:          template.Signature,
		SignatureAlgorithm: template.SignatureAlgorithm,
		Issuer:             s.Root.Subject,
	}

	leafCertRaw, err := x509.CreateCertificate(rand.Reader, &tbs, s.Root, template.PublicKey, s.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create leaf certificate: %w", err)
	}

	leafCert, err := x509.ParseCertificate(leafCertRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	return leafCert, nil
}

func newRootCert(key *ecdsa.PrivateKey) (*x509.Certificate, error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName: "example.org",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	caCert, err := x509.ParseCertificate(caBytes)
	return caCert, err
}
