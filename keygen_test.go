package subtlecrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	_ "bitbucket.org/mikehouston/browsertests"
)

func TestAESKeyGen(t *testing.T) {
	t.Log("Generate AES Key")
	_, err := GenerateSymmetricKey(AES_GCM(AES_256), true)
	if err != nil {
		t.Error(err)
	}
}

func TestRSAKeyGen(t *testing.T) {
	t.Log("Generate RSA KeyPair")
	start := time.Now()
	_, err := GenerateRSAKeyPair(RSASSA_PKCS1_v1_5(2048, SHA_256), true)
	if err != nil {
		t.Error(err)
	}
	t.Log("Took", time.Now().Sub(start).String())
}

func TestECKeyGen(t *testing.T) {
	t.Log("Generate EC KeyPair")
	start := time.Now()
	_, err := GenerateECKeyPair(ECDSA(P_256), true)
	if err != nil {
		t.Error(err)
	}
	t.Log("Took", time.Now().Sub(start).String())
}

func TestStdlibKeyGen(t *testing.T) {
	t.Skip("Stdlib keygen is very slow - skipping")

	t.Log("Generate RSA KeyPair using crypto/rsa")
	start := time.Now()
	_, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}
	t.Log("Took", time.Now().Sub(start).String())
}

func BenchmarkRSAKeyGen_Subtle(b *testing.B) {
	for n := 0; n < b.N; n++ {
		GenerateRSAKeyPair(RSASSA_PKCS1_v1_5(2048, SHA_256), true)
	}
}
