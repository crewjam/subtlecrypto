package subtlecrypto

import (
	"crypto/rand"

	"bitbucket.org/kevalin-p2p/subtlecrypto/jwk"
	"github.com/gopherjs/gopherjs/js"
)

func (k *PublicKey) WrapSymmetric(toWrap *CryptoKey) ([]byte, error) {
	algo := k.Algorithm
	result, err := subtle.CallAsync("wrapKey", RAW, toWrap, k, algo)
	if err != nil {
		return nil, err
	}

	return getBytes(result), nil
}

func (k *PrivateKey) UnwrapSymmetric(wrappedKey []byte, target *Symmetric, extractable bool, uses ...Use) (*CryptoKey, error) {
	algo := k.Algorithm
	if len(uses) == 0 {
		uses = target.Uses
	}

	result, err := subtle.CallAsync("unwrapKey", RAW, wrappedKey, k, algo, target, extractable, uses)
	if err != nil {
		return nil, err
	}

	return &CryptoKey{Object: result}, nil
}

func (k *CryptoKey) WrapWithIV(toWrap *PrivateKey, iv []byte) (*jwk.Key, error) {
	args := &EncryptionArgs{Object: js.Global.Get("Object").New()}
	args.Name = k.Algorithm.Name
	args.IV = iv

	result, err := subtle.CallAsync("wrapKey", JWK, toWrap, k, args)
	if err != nil {
		return nil, err
	}

	return &jwk.Key{Object: result}, nil
}

func (k *CryptoKey) WrapPrivateKey(toWrap *PrivateKey) (*jwk.Key, []byte, error) {
	iv := make([]byte, 12)
	_, err := rand.Reader.Read(iv)
	if err != nil {
		return nil, nil, err
	}
	result, err := k.WrapWithIV(toWrap, iv)
	return result, iv, err
}

func (k *CryptoKey) UnwrapPrivateKey(wrappedKey *jwk.Key, iv []byte, target *Algorithm, extractable bool, uses ...Use) (*PrivateKey, error) {
	args := &EncryptionArgs{Object: js.Global.Get("Object").New()}
	args.Name = k.Algorithm.Name
	args.IV = iv

	if len(uses) == 0 {
		uses = target.Uses
	}

	result, err := subtle.CallAsync("unwrapKey", JWK, wrappedKey, k, args, target, extractable, uses)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{&CryptoKey{Object: result}}, nil
}
