// +build js

package subtlecrypto

import (
	"github.com/gopherjs/gopherjs/js"
)

// Algorithms
var (
	AES_CBC           = newSymmetric("AES-CBC", ENCRYPT, DECRYPT, WRAP_KEY, UNWRAP_KEY)
	AES_CTR           = newSymmetric("AES-CTR", ENCRYPT, DECRYPT, WRAP_KEY, UNWRAP_KEY)
	AES_GCM           = newSymmetric("AES-GCM", ENCRYPT, DECRYPT, WRAP_KEY, UNWRAP_KEY)
	RSA_OAEP          = newRSA("RSA-OAEP", ENCRYPT, DECRYPT, WRAP_KEY, UNWRAP_KEY)
	AES_KW            = newSymmetric("AES-KW", WRAP_KEY, UNWRAP_KEY)
	HMAC              = newSymmetricWithHash("HMAC", SIGN, VERIFY)
	RSA_PSS           = newRSA("RSA-PSS", SIGN, VERIFY)
	RSASSA_PKCS1_v1_5 = newRSA("RSASSA-PKCS1-v1_5", SIGN, VERIFY)
	ECDSA             = newEC("ECDSA", SIGN, VERIFY)
	ECDH              = newEC("ECDH", DERIVE_KEY, DERIVE_BITS)
	DH                = newSymmetric("DH", DERIVE_KEY, DERIVE_BITS)
)

type NamedCurve string

var (
	P_256 NamedCurve = "P-256"
	P_384 NamedCurve = "P-384"
	P_512 NamedCurve = "P-521"
)

type Algorithm struct {
	*js.Object
	Name string `js:"name"`
	Uses []Use
}

func newAlgorithm(name string, uses ...Use) *Algorithm {
	a := &Algorithm{Object: js.Global.Get("Object").New()}
	a.Name = name
	a.Uses = uses
	return a
}

// Encryption algorithms
type Symmetric struct {
	*Algorithm
	Length int `js:"length"`
}

func newSymmetric(name string, uses ...Use) func(length int) *Symmetric {
	return func(length int) *Symmetric {
		a := &Symmetric{Algorithm: newAlgorithm(name, uses...)}
		a.Length = length
		return a
	}
}

type SymmetricWithHash struct {
	*Symmetric
	Hash *Hash `js:"hash"`
}

func newSymmetricWithHash(name string, uses ...Use) func(length int, hash *Hash) *SymmetricWithHash {
	return func(length int, hash *Hash) *SymmetricWithHash {
		a := &Symmetric{Algorithm: newAlgorithm(name, uses...)}
		a.Length = length

		ah := &SymmetricWithHash{Symmetric: a}
		ah.Hash = hash
		return ah
	}
}

type RSA struct {
	*Algorithm
	ModulusLength  int    `js:"modulusLength"`
	PublicExponent []byte `js:"publicExponent"`
	Hash           *Hash  `js:"hash"`
}

func newRSA(name string, uses ...Use) func(modulusLength int, hash *Hash) *RSA {
	return func(modulusLength int, hash *Hash) *RSA {
		a := &RSA{Algorithm: newAlgorithm(name, uses...)}
		a.ModulusLength = modulusLength
		a.PublicExponent = []byte{0x01, 0x00, 0x01}
		a.Hash = hash
		return a
	}
}

type EC struct {
	*Algorithm
	NamedCurve NamedCurve `js:"namedCurve"`
}

func newEC(name string, uses ...Use) func(namedCurve NamedCurve) *EC {
	return func(namedCurve NamedCurve) *EC {
		a := &EC{Algorithm: newAlgorithm(name, uses...)}
		a.NamedCurve = namedCurve
		return a
	}
}
