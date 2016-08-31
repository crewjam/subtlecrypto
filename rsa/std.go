// +build !js

package rsa

import (
	"crypto/rand"
	"crypto/rsa"
)

type PublicKey struct {
	key *rsa.PublicKey
}

type PrivateKey struct {
	PublicKey *PublicKey
	key       *rsa.PrivateKey
}

// GenerateKey generates an RSA keypair of the given bit size
func GenerateKey(bits int) (*PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{
		PublicKey: &PublicKey{
			key: &privateKey.PublicKey,
		},
		key: privateKey,
	}, nil
}
