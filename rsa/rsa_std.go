// +build !js

package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"io"

	"bitbucket.org/kevalin-p2p/subtlecrypto/hash"
	stdhash "hash"
)

type PublicKey struct {
	key *rsa.PublicKey
}

type PrivateKey struct {
	PublicKey *PublicKey
	key       *rsa.PrivateKey
}

func stdHash(h hash.Hash) stdhash.Hash {
	switch h {
	case hash.SHA_1:
		return sha1.New()
	case hash.SHA_256:
		return sha256.New()
	case hash.SHA_384:
		return sha512.New384()
	case hash.SHA_512:
		return sha512.New()
	default:
		return nil
	}
}

type algorithm struct {
	bits int
	rand io.Reader
	hash stdhash.Hash
}

// GenerateKey generates an RSA keypair of the given bit size
func (a *algorithm) GenerateKey(exportable bool) (*PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, a.bits)
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

type oaep struct {
	*algorithm
}

func (a *oaep) Encrypt(pub *PublicKey, msg []byte) ([]byte, error) {
	return rsa.EncryptOAEP(a.hash, a.rand, pub.key, msg, nil)
}

func RSA_OAEP(bits int, h hash.Hash) RSA {
	sh := stdHash(h)
	return &oaep{
		&algorithm{
			bits: bits,
			rand: rand.Reader,
			hash: sh,
		},
	}
}
