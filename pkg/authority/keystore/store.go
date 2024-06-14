package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func NewPrivateKey() (*ecdsa.PrivateKey, error) {
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return caPrivKey, nil
}
