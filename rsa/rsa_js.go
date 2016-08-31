// +build js

package rsa

import (
	"bitbucket.org/kevalin-p2p/subtlecrypto"
	"bitbucket.org/kevalin-p2p/subtlecrypto/hash"
)

type PublicKey struct {
	key *subtlecrypto.PublicKey
}

type PrivateKey struct {
	PublicKey *PublicKey
	key       *subtlecrypto.PrivateKey
}

type algorithm struct {
	algo *subtlecrypto.RSA
}

func subtleHash(h hash.Hash) *subtlecrypto.Hash {
	switch h {
	case hash.SHA_1:
		return subtlecrypto.SHA_1
	case hash.SHA_256:
		return subtlecrypto.SHA_256
	case hash.SHA_384:
		return subtlecrypto.SHA_384
	case hash.SHA_512:
		return subtlecrypto.SHA_512
	default:
		return nil
	}
}

func RSA_OAEP(bits int, h hash.Hash) RSA {
	sh := subtleHash(h)
	algo := subtlecrypto.RSA_OAEP(bits, sh)
	return &algorithm{
		algo,
	}
}

// GenerateKey generates an RSA keypair of the given bit size
func (a *algorithm) GenerateKey(exportable bool) (*PrivateKey, error) {
	keypair, err := subtlecrypto.GenerateRSAKeyPair(a.algo, exportable)
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

func (a *algorithm) Encrypt(pub *PublicKey, msg []byte) ([]byte, error) {
	return pub.key.Encrypt(msg)
}
