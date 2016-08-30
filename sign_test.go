package subtlecrypto

import (
	"testing"

	_ "bitbucket.org/mikehouston/browsertests"
)

func TestRSASign(t *testing.T) {
	t.Log("Generate RSA KeyPair")
	keypair, err := GenerateRSAKeyPair(RSASSA_PKCS1_v1_5(2048, SHA_256), true)
	if err != nil {
		t.Error(err)
	}

	t.Log("Sign string")
	sig, err := keypair.PrivateKey.Sign([]byte("Hello"))
	if err != nil {
		t.Error(err)
	}
	t.Log(sig)
}

func TestRSAVerify(t *testing.T) {
	t.Log("Generate RSA KeyPair")
	keypair, err := GenerateRSAKeyPair(RSASSA_PKCS1_v1_5(2048, SHA_256), true)
	if err != nil {
		t.Error(err)
	}

	t.Log("Sign string")
	msg := []byte("Hello")
	sig, err := keypair.PrivateKey.Sign(msg)
	if err != nil {
		t.Error(err)
	}

	t.Log("Verify signature")
	isValid, err := keypair.PublicKey.Verify(sig, msg)
	if err != nil {
		t.Error(err)
	}
	t.Log("Signature is valid:", isValid)
}
