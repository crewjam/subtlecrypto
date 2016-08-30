package subtlecrypto

func (k *BrowserKey) Sign(data []byte) ([]byte, error) {
	algo := k.Algorithm
	signature, err := subtle.CallAsync("sign", algo, k, data)
	if err != nil {
		return nil, err
	}

	return getBytes(signature), nil
}

func (k *BrowserKey) Verify(signature, data []byte) (bool, error) {
	algo := k.Algorithm
	isValid, err := subtle.CallAsync("verify", algo, k, signature, data)
	if err != nil {
		return false, err
	}

	return isValid.Bool(), nil
}
