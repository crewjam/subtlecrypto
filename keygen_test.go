package subtlecrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"time"

	"testing"
)

func TestAESKeyGen(t *testing.T) {
	println("Generate AES Key")
	key, err := GenerateSymmetricKey(AES_CBC(AES_256), true)
	if err != nil {
		t.Error(err)
	}
	str, _ := key.Export(PKCS8)
	println(str)
}

func TestRSAKeyGen(t *testing.T) {
	println("Generate RSA KeyPair")
	start := time.Now()
	keypair, err := GenerateRSAKeyPair(RSASSA_PKCS1_v1_5(2048, SHA_256), true)
	if err != nil {
		t.Error(err)
	}
	println("Took", time.Now().Sub(start).String())

	public, _ := keypair.PublicKey.Export(JWK)
	println("Public:", public)
	private, _ := keypair.PrivateKey.Export(JWK)
	println("Private:", private)
}

func TestECKeyGen(t *testing.T) {
	println("Generate EC KeyPair")
	start := time.Now()
	keypair, err := GenerateECKeyPair(ECDSA(P_256), true)
	if err != nil {
		t.Error(err)
	}
	println("Took", time.Now().Sub(start).String())

	public, _ := keypair.PublicKey.Export(JWK)
	println("Public:", public)
	private, _ := keypair.PrivateKey.Export(JWK)
	println("Private:", private)
}

func TestStdlibKeyGen(t *testing.T) {
	t.Skip("Stdlib keygen is very slow - skipping")

	println("Generate RSA KeyPair using crypto/rsa")
	start := time.Now()
	keypair2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}
	println("Took", time.Now().Sub(start).String())
	println(keypair2)
}

func BenchmarkRSAKeyGen_Subtle(b *testing.B) {
	for n := 0; n < b.N; n++ {
		GenerateRSAKeyPair(RSASSA_PKCS1_v1_5(2048, SHA_256), true)
	}
}
