package subtlecrypto

import (
	"testing"

	_ "bitbucket.org/mikehouston/browsertests"
)

func TestAESEncrypt(t *testing.T) {
	t.Log("Generate AES Key")
	key, err := GenerateSymmetricKey(AES_GCM(AES_256), true)
	if err != nil {
		t.Error(err)
	}

	plaintext := []byte("Hello World")
	t.Log("Encrypt plaintext:", string(plaintext))
	cyphertext, iv, err := key.Encrypt(plaintext)
	if err != nil {
		t.Error(err)
	}

	t.Log("Cyphertext:", cyphertext)
	t.Log("IV:", iv)
}

func TestAESDecrypt(t *testing.T) {
	t.Log("Generate AES Key")
	key, err := GenerateSymmetricKey(AES_GCM(AES_256), true)
	if err != nil {
		t.Error(err)
	}

	plaintext := []byte("Hello World")
	t.Log("Encrypt plaintext:", string(plaintext))
	cyphertext, iv, err := key.Encrypt(plaintext)
	if err != nil {
		t.Error(err)
	}

	t.Log("Decrypt cyphertext")
	decrypted, err := key.Decrypt(cyphertext, iv)
	if err != nil {
		t.Error(err)
	}

	t.Log(string(decrypted))
	if string(decrypted) != string(plaintext) {
		t.Error("Plaintext does not match decrypted message")
	}
}
