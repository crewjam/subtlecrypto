package subtlecrypto

import (
	"encoding/hex"
	"testing"

	_ "bitbucket.org/mikehouston/browsertests"
)

func TestSHA1Digest(t *testing.T) {

	message := "The quick brown fox jumps over the lazy dog"
	digest := "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"

	t.Log("Digest string: ", message)
	d, err := SHA_1.Digest([]byte(message))
	if err != nil {
		t.Error(err)
	}
	h := hex.EncodeToString(d)
	t.Log(h)
	if h != digest {
		t.Error("Digest is incorrect")
	}
}

func TestSHA256Digest(t *testing.T) {

	message := "The quick brown fox jumps over the lazy dog"
	digest := "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"

	t.Log("Digest string: ", message)
	d, err := SHA_256.Digest([]byte(message))
	if err != nil {
		t.Error(err)
	}
	h := hex.EncodeToString(d)
	t.Log(h)
	if h != digest {
		t.Error("Digest is incorrect")
	}
}

func TestSHA384Digest(t *testing.T) {

	message := "The quick brown fox jumps over the lazy dog"
	digest := "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1"

	t.Log("Digest string: ", message)
	d, err := SHA_384.Digest([]byte(message))
	if err != nil {
		t.Error(err)
	}
	h := hex.EncodeToString(d)
	t.Log(h)
	if h != digest {
		t.Error("Digest is incorrect")
	}
}

func TestSHA512Digest(t *testing.T) {

	message := "The quick brown fox jumps over the lazy dog"
	digest := "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"

	t.Log("Digest string: ", message)
	d, err := SHA_512.Digest([]byte(message))
	if err != nil {
		t.Error(err)
	}
	h := hex.EncodeToString(d)
	t.Log(h)
	if h != digest {
		t.Error("Digest is incorrect")
	}
}
