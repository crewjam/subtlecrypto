// +build js

package subtlecrypto

import (
	"github.com/gopherjs/gopherjs/js"
)

type ExportFormat string

var (
	JWK   ExportFormat = "jwk"  // (public or private)
	RAW   ExportFormat = "raw"  //  (public only)
	SPKI  ExportFormat = "spki" // (public only)
	PKCS8 ExportFormat = "pkcs8"
)

type CryptoKey struct {
	*js.Object
	Algorithm *Algorithm `js:"algorithm"`
}

type CryptoKeyPair struct {
	*js.Object

	PublicKey  *CryptoKey `js:"publicKey"`
	PrivateKey *CryptoKey `js:"privateKey"`
}

func GenerateSymmetricKey(algo *Symmetric, extractable bool, uses ...Use) (*CryptoKey, error) {
	if len(uses) == 0 {
		uses = algo.Uses
	}

	key, err := subtle.CallAsync("generateKey", algo, extractable, uses)

	if err != nil {
		return nil, err
	}
	return &CryptoKey{Object: key}, nil
}

func GenerateRSAKeyPair(algo *RSA, extractable bool, uses ...Use) (*CryptoKeyPair, error) {
	if len(uses) == 0 {
		uses = algo.Uses
	}

	keypair, err := subtle.CallAsync("generateKey", algo, extractable, uses)

	if err != nil {
		return nil, err
	}
	return &CryptoKeyPair{Object: keypair}, nil
}

func GenerateECKeyPair(algo *EC, extractable bool, uses ...Use) (*CryptoKeyPair, error) {
	if len(uses) == 0 {
		uses = algo.Uses
	}

	keypair, err := subtle.CallAsync("generateKey", algo, extractable, uses)

	if err != nil {
		return nil, err
	}
	return &CryptoKeyPair{Object: keypair}, nil
}
