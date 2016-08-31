package rsa

import (
	"testing"

	"bitbucket.org/kevalin-p2p/subtlecrypto/hash"
	_ "bitbucket.org/mikehouston/browsertests"
)

func TestKeyGen(t *testing.T) {
	algo := RSA_OAEP(2048, hash.SHA_256)
	key, err := algo.GenerateKey(true)
	if err != nil {
		t.Error(err)
	}
	println(key)
}

func TestEncrypt(t *testing.T) {
	algo := RSA_OAEP(2048, hash.SHA_256)
	key, err := algo.GenerateKey(true)
	if err != nil {
		t.Error(err)
	}

	msg := []byte("Hello world")
	ct, err := algo.Encrypt(key.PublicKey, msg)
	if err != nil {
		t.Error(err)
	}

	t.Logf("%+v", ct)
}
