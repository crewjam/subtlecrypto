package subtlecrypto

import (
	"testing"
)

func TestWrapAESWithRSA(t *testing.T) {
	// Generate AES key
	target := AES_GCM(AES_256)
	aes, err := GenerateSymmetricKey(target, true)
	if err != nil {
		t.Error(err)
	}

	// Encrypt test message
	message := "The quick brown fox jumps over the lazy dog"
	ct, iv, err := aes.Encrypt([]byte(message))
	if err != nil {
		t.Error(err)
	}

	// Generate RSA key
	rsa, err := GenerateRSAKeyPair(RSA_OAEP(2048, SHA_256), true)
	if err != nil {
		t.Error(err)
	}

	// Wrap key
	wrappedKey, err := rsa.PublicKey.WrapSymmetric(aes)
	if err != nil {
		t.Error(err)
	}

	// Unwrap key
	unwrappedKey, err := rsa.PrivateKey.UnwrapSymmetric(wrappedKey, target, true)
	if err != nil {
		t.Error(err)
	}

	// Decrypt test message
	pt, err := unwrappedKey.Decrypt(ct, iv)
	if err != nil {
		t.Error(err)
	}
	t.Log(string(pt))
}

func TestWrapRSAWithAES(t *testing.T) {

	// Generate RSA key
	target := RSA_OAEP(2048, SHA_256)
	rsa, err := GenerateRSAKeyPair(target, true)
	if err != nil {
		t.Error(err)
	}

	// Generate AES key
	aes, err := GenerateSymmetricKey(AES_GCM(AES_256), true)
	if err != nil {
		t.Error(err)
	}

	// Encrypt test message
	message := "The quick brown fox jumps over the lazy dog"
	ct, err := rsa.PublicKey.Encrypt([]byte(message))
	if err != nil {
		t.Error(err)
	}

	// Wrap key
	wrappedKey, iv, err := aes.WrapPrivateKey(rsa.PrivateKey)
	if err != nil {
		t.Error(err)
	}

	// Unwrap key
	unwrappedKey, err := aes.UnwrapPrivateKey(wrappedKey, iv, target.Algorithm, true, DECRYPT)
	if err != nil {
		t.Error(err)
	}

	// Decrypt test message
	pt, err := unwrappedKey.Decrypt(ct)
	if err != nil {
		t.Error(err)
	}
	t.Log(string(pt))
}
