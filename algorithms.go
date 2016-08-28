// +build js

package subtlecrypto

import (
	"github.com/gopherjs/gopherjs/js"
)

// Algorithms
var (
	AES_CBC           = newAES("AES-CBC", ENCRYPT, DECRYPT, WRAP_KEY, UNWRAP_KEY)
	AES_CMAC          = newAES("AES-CMAC", SIGN, VERIFY)
	AES_CTR           = newAES("AES-CTR", ENCRYPT, DECRYPT, WRAP_KEY, UNWRAP_KEY)
	AES_GCM           = newAES("AES-GCM", ENCRYPT, DECRYPT, WRAP_KEY, UNWRAP_KEY)
	AES_KW            = newAES("AES-KW", WRAP_KEY, UNWRAP_KEY)
	DH                = newDH("DH", DERIVE_KEY, DERIVE_BITS)
	ECDH              = newEC("ECDH", DERIVE_KEY, DERIVE_BITS)
	ECDSA             = newEC("ECDSA", SIGN, VERIFY)
	HMAC              = newHMAC("HMAC", SIGN, VERIFY)
	RSA_OAEP          = newRSA("RSA-OAEP", ENCRYPT, DECRYPT, WRAP_KEY, UNWRAP_KEY)
	RSA_PSS           = newRSA("RSA-PSS", SIGN, VERIFY)
	RSASSA_PKCS1_v1_5 = newRSA("RSASSA-PKCS1-v1_5", SIGN, VERIFY)
)

type AESLength int

var (
	AES_128 AESLength = 128
	AES_192 AESLength = 192
	AES_256 AESLength = 256
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

func newAES(name string, uses ...Use) func(length AESLength) *Symmetric {
	return func(length AESLength) *Symmetric {
		a := &Symmetric{Algorithm: newAlgorithm(name, uses...)}
		a.Length = int(length)
		return a
	}
}

type SymmetricWithHash struct {
	*Symmetric
	Hash *Hash `js:"hash"`
}

func newHMAC(name string, uses ...Use) func(hash *Hash, length ...int) *SymmetricWithHash {
	return func(hash *Hash, length ...int) *SymmetricWithHash {
		a := &Symmetric{Algorithm: newAlgorithm(name, uses...)}
		if len(length) > 0 {
			a.Length = length[0]
		}

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

type DHArgs struct {
	*Algorithm
	Prime     []byte `js:"prime"`
	Generator []byte `js:"generator"`
}

func newDH(name string, uses ...Use) func(prime, generator []byte) *DHArgs {
	return func(prime, generator []byte) *DHArgs {
		a := &DHArgs{Algorithm: newAlgorithm(name, uses...)}
		a.Prime = prime
		a.Generator = generator
		return a
	}
}
