package subtlecrypto

import (
	"crypto/rand"

	"github.com/gopherjs/gopherjs/js"
)

type EncryptionArgs struct {
	*js.Object
	Name           string `js:"name"`
	IV             []byte `js:"iv"`
	AdditionalData []byte `js:"additionalData"`
	TagLength      int    `js:"tagLength"`
}

func (k *CryptoKey) EncryptWithIV(plaintext []byte, iv []byte) ([]byte, error) {
	args := &EncryptionArgs{Object: js.Global.Get("Object").New()}
	args.Name = k.Algorithm.Name
	args.IV = iv

	cyphertext, err := subtle.CallAsync("encrypt", args, k, plaintext)
	if err != nil {
		return nil, err
	}

	return getBytes(cyphertext), nil
}

func (k *CryptoKey) Encrypt(plaintext []byte) (cyphertext []byte, iv []byte, err error) {
	iv = make([]byte, 12)
	_, err = rand.Reader.Read(iv)
	if err != nil {
		return nil, nil, err
	}
	cyphertext, err = k.EncryptWithIV(plaintext, iv)
	return
}

func (k *CryptoKey) Decrypt(cyphertext []byte, iv []byte) ([]byte, error) {
	args := &EncryptionArgs{Object: js.Global.Get("Object").New()}
	args.Name = k.Algorithm.Name
	args.IV = iv

	plaintext, err := subtle.CallAsync("decrypt", args, k, cyphertext)
	if err != nil {
		return nil, err
	}

	return getBytes(plaintext), nil
}

func (k *PublicKey) Encrypt(plaintext []byte) (cyphertext []byte, err error) {
	buffer, err := subtle.CallAsync("encrypt", k.Algorithm, k, plaintext)
	if err != nil {
		return nil, err
	}

	return getBytes(buffer), nil
}

func (k *PrivateKey) Decrypt(cyphertext []byte) (plaintext []byte, err error) {
	buffer, err := subtle.CallAsync("decrypt", k.Algorithm, k, cyphertext)
	if err != nil {
		return nil, err
	}

	return getBytes(buffer), nil
}
