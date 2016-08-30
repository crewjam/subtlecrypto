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

type BrowserKey struct {
	*js.Object
	Algorithm *Algorithm `js:"algorithm"`
}

type BrowserKeyPair struct {
	*js.Object

	PublicKey  *BrowserKey `js:"publicKey"`
	PrivateKey *BrowserKey `js:"privateKey"`
}

func GenerateSymmetricKey(algo *Symmetric, extractable bool, uses ...Use) (*BrowserKey, error) {
	if len(uses) == 0 {
		uses = algo.Uses
	}

	println("Generating", algo.Name, "key for", uses)

	key, err := subtle.CallAsync("generateKey", algo, extractable, uses)

	if err != nil {
		return nil, err
	}
	return &BrowserKey{Object: key}, nil
}

func GenerateRSAKeyPair(algo *RSA, extractable bool, uses ...Use) (*BrowserKeyPair, error) {
	if len(uses) == 0 {
		uses = algo.Uses
	}

	println("Generating", algo.Name, "key for", uses)
	keypair, err := subtle.CallAsync("generateKey", algo, extractable, uses)

	if err != nil {
		return nil, err
	}
	return &BrowserKeyPair{Object: keypair}, nil
}

func GenerateECKeyPair(algo *EC, extractable bool, uses ...Use) (*BrowserKeyPair, error) {
	if len(uses) == 0 {
		uses = algo.Uses
	}

	println("Generating", algo.Name, "key for", uses)
	keypair, err := subtle.CallAsync("generateKey", algo, extractable, uses)

	if err != nil {
		return nil, err
	}
	return &BrowserKeyPair{Object: keypair}, nil
}
