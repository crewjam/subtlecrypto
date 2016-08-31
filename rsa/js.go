// +build js

package rsa

import (
	"bitbucket.org/kevalin-p2p/subtlecrypto"
)

type PublicKey struct {
	key *subtlecrypto.CryptoKey
}

type PrivateKey struct {
	PublicKey *PublicKey
	key       *subtlecrypto.CryptoKey
}

// GenerateKey generates an RSA keypair of the given bit size
func GenerateKey(bits int) (*PrivateKey, error) {
	algo := subtlecrypto.RSA_OAEP(bits, subtlecrypto.SHA_256)
	keypair, err := subtlecrypto.GenerateRSAKeyPair(algo, true)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{
		PublicKey: &PublicKey{
			key: keypair.PublicKey,
		},
		key: keypair.PrivateKey,
	}, nil
}
