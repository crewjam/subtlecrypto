package subtlecrypto

func (h *Hash) Digest(message []byte) (digest []byte, err error) {
	buffer, err := subtle.CallAsync("digest", h, message)
	if err != nil {
		return nil, err
	}

	return getBytes(buffer), nil
}
