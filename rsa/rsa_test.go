package rsa

import (
	"testing"

	_ "bitbucket.org/mikehouston/browsertests"
)

func TestKeyGen(t *testing.T) {
	key, err := GenerateKey(2048)
	if err != nil {
		t.Error(err)
	}
	println(key)
}
