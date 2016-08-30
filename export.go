package subtlecrypto

import (
	"encoding/hex"

	"github.com/gopherjs/gopherjs/js"
)

func (k *BrowserKey) Export(format ExportFormat) (string, error) {
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
