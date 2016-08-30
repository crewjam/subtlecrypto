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

func (k *BrowserKey) Encrypt(plaintext []byte, iv []byte) ([]byte, []byte, error) {
	args := &EncryptionArgs{Object: js.Global.Get("Object").New()}
	args.Name = k.Algorithm.Name

	if iv == nil {
		iv = make([]byte, 12)
		_, err := rand.Reader.Read(iv)
		if err != nil {
			return nil, nil, err
		}
	}
	args.IV = iv

	cyphertext, err := subtle.CallAsync("encrypt", args, k, plaintext)
	if err != nil {
		return nil, nil, err
	}

	return getBytes(cyphertext), iv, nil
}

func (k *BrowserKey) Decrypt(cyphertext []byte, iv []byte) ([]byte, error) {
	args := &EncryptionArgs{Object: js.Global.Get("Object").New()}
	args.Name = k.Algorithm.Name
	args.IV = iv

	plaintext, err := subtle.CallAsync("decrypt", args, k, cyphertext)
	if err != nil {
		return nil, err
	}

	return getBytes(plaintext), nil
}
