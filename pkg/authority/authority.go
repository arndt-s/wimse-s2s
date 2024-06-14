package authority

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwk"
	"ietf.org/wimse/s2s/pkg/authority/certstore"
	"ietf.org/wimse/s2s/pkg/authority/keystore"
)

const tokenLifetime = 5 * time.Minute

type Authority struct {
	domain url.URL
	jwt    *certstore.Store
	x509   *certstore.Store
}

func NewAuthority(domain url.URL) (*Authority, error) {
	jwt, err := newStore()
	if err != nil {
		return nil, err
	}

	x509, err := newStore()
	if err != nil {
		return nil, err
	}

	return &Authority{
		domain: domain,
		jwt:    jwt,
		x509:   x509,
	}, nil
}

func (a *Authority) IssueJWTSvid(sub *url.URL, publicKey interface{}) (string, error) {
	if publicKey == nil {
		return "", fmt.Errorf("public key is nil")
	}
	key, err := jwk.New(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to build JWK: %w", err)
	}

	// TODO: is that so?
	if _, ok := key.(jwk.SymmetricKey); ok {
		return "", fmt.Errorf("Symmetric keys are not allowed")
	}

	method := jwt.SigningMethodES384
	t := &jwt.Token{
		Header: map[string]interface{}{
			"typ": "wimse-id+jwt",
			"alg": method.Alg(),
		},
		Claims: jwt.MapClaims{
			"iss": a.domain.String(), // TODO
			"sub": sub.String(),
			"exp": time.Now().Unix() + int64(tokenLifetime),
			"jti": uuid.New().String(),
			"cnf": map[string]interface{}{
				"jwk": key,
			},
		},
		Method: method,
	}

	return t.SignedString(a.jwt.Key)
}

func (a *Authority) IssueX509Svid(sub *url.URL) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := keystore.NewPrivateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create private key: %w", err)
	}

	t := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: sub.String(),
		},
		SignatureAlgorithm: x509.ECDSAWithSHA384,
		PublicKey:          key.PublicKey,
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &t, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	cert, err := a.x509.IssueLeaf(csr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to issue certificate: %w", err)
	}

	return cert, key, nil
}

func (a *Authority) GetJWTPublicKey() *ecdsa.PublicKey {
	return &a.jwt.Key.PublicKey
}

func newStore() (*certstore.Store, error) {
	key, err := keystore.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to create private key: %w", err)
	}

	return certstore.New(key)
}
