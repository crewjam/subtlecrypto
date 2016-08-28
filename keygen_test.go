package subtlecrypto

import (
    "time"
	"crypto/rand"
	"crypto/rsa"

	"testing"
)

func TestSubtleKeyGen(t *testing.T) {
	println("Generate AES Key")
	key, err := GenerateKey()
	if err != nil {
		t.Error(err)
	}
	println(key)

	println("Generate RSA KeyPair")
    start := time.Now()
	keypair, err := GenerateKeyPair()
	if err != nil {
		t.Error(err)
	}
	println("Took", time.Now().Sub(start).String())
	println(keypair)
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
		GenerateKeyPair()
	}
}

func BenchmarkRSAKeyGen_Stdlib(b *testing.B) {
	for n := 0; n < b.N; n++ {
		rsa.GenerateKey(rand.Reader, 2048)
	}
}
