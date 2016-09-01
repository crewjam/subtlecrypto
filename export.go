package subtlecrypto

import (
	"encoding/hex"

	"github.com/gopherjs/gopherjs/js"

	"bitbucket.org/kevalin-p2p/subtlecrypto/jwk"
)

func (k *CryptoKey) ExportJWK() (*jwk.Key, error) {
	exportedKey, err := subtle.CallAsync("exportKey", JWK, k)
	if err != nil {
		return nil, err
	}

	return &jwk.Key{Object: exportedKey}, nil
}

func (a *Algorithm) ImportJWK(key *jwk.Key, exportable bool, uses ...Use) (*CryptoKey, error) {
	if len(uses) == 0 {
		uses = a.Uses
	}

	// The Algorithm object 'a' wraps a js.Object, which will pass all algorithm
	// information to the call to importKey, not just the fields defined in Algorithm.
	// Otherwise we would need to override this method in RSA
	importedKey, err := subtle.CallAsync("importKey", JWK, key, a, exportable, uses)
	if err != nil {
		return nil, err
	}

	return &CryptoKey{Object: importedKey}, nil
}

func (k *CryptoKey) Export(format ExportFormat) (string, error) {
	exportedKey, err := subtle.CallAsync("exportKey", format, k)
	if err != nil {
		return "", err
	}

	switch format {
	case JWK:
		output := js.Global.Get("JSON").Call("stringify", exportedKey, nil, 3)
		return output.String(), nil
	case PKCS8:
		return hex.EncodeToString(getBytes(exportedKey)), nil
	default:
		return string(getBytes(exportedKey)), nil
	}
}

func (a *Algorithm) Import(key string, format ExportFormat, exportable bool, uses ...Use) (*CryptoKey, error) {
	if len(uses) == 0 {
		uses = a.Uses
	}

	var keyData interface{}
	switch format {
	case JWK:
		keyData = js.Global.Get("JSON").Call("parse", key)
	case PKCS8:
		bytes, err := hex.DecodeString(key)
		if err != nil {
			return nil, err
		}
		keyData = js.NewArrayBuffer(bytes)
	default:
		keyData = js.NewArrayBuffer([]byte(key))
	}

	// The Algorithm object 'a' wraps a js.Object, which will pass all algorithm
	// information to the call to importKey, not just the fields defined in Algorithm.
	// Otherwise we would need to override this method in RSA
	importedKey, err := subtle.CallAsync("importKey", format, keyData, a, exportable, uses)
	if err != nil {
		return nil, err
	}

	return &CryptoKey{Object: importedKey}, nil
}
