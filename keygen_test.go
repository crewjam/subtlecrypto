package subtlecrypto

import (
	"testing"
)

func TestKeyGen(t *testing.T) {
	println("Generate AES Key")
	key, err := GenerateKey()
	println(key, err)

	println("Generate RSA KeyPair")
	keypair, err := GenerateKeyPair()
	println(keypair, err)
}
