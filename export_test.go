package subtlecrypto

import (
	"testing"

	_ "bitbucket.org/mikehouston/browsertests"
)

func TestAESImport(t *testing.T) {
	t.Log("Generate AES Key")
	key, err := GenerateSymmetricKey(AES_GCM(AES_256), true)
	if err != nil {
		t.Error(err)
	}

	pt := []byte("Hello world")
	ct, iv, err := key.Encrypt(pt)
	if err != nil {
		t.Error(err)
	}

	str, err := key.Export(JWK)
	if err != nil {
		t.Error(err)
	}
	t.Log(str)

	importedKey, err := AES_GCM(AES_256).Import(str, JWK, true)
	if err != nil {
		t.Error(err)
	}
	t.Log("Imported Key")

	// Decrypt ct
	dt, err := importedKey.Decrypt(ct, iv)
	if err != nil {
		t.Error(err)
	}

	if string(pt) != string(dt) {
		t.Error("Decoded data does not match the original message")
	}
}

func TestRSAImport(t *testing.T) {
	t.Log("Generate RSA KeyPair")
	keypair, err := GenerateRSAKeyPair(RSASSA_PKCS1_v1_5(2048, SHA_256), true)
	if err != nil {
		t.Error(err)
	}

	pt := []byte("Hello world")
	sig, err := keypair.PrivateKey.Sign(pt)
	if err != nil {
		t.Error(err)
	}

	str, err := keypair.PublicKey.Export(JWK)
	if err != nil {
		t.Error(err)
	}
	t.Log(str)

	importedKey, err := RSASSA_PKCS1_v1_5(2048, SHA_256).Import(str, JWK, true, VERIFY)
	if err != nil {
		t.Error(err)
	}
	t.Log("Imported Key")

	// Decrypt ct
	isValid, err := importedKey.Verify(sig, pt)
	if err != nil {
		t.Error(err)
	}

	if !isValid {
		t.Error("Imported key cannot verify signature")
	}
}

// func TestECImport(t *testing.T) {
// 	t.Log("Generate EC KeyPair")
// 	keypair, err := GenerateECKeyPair(ECDSA(P_256), true)
// 	if err != nil {
// 		t.Error(err)
// 	}
// }
