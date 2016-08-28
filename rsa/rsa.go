// +build js

package rsa

import (
	"crypto/rsa"
)

// GenerateKey generates an RSA keypair of the given bit size using the
// random source random (for example, crypto/rand.Reader).
func GenerateKey(random io.Reader, bits int) (*rsa.PrivateKey, error) {
	
}
