// Package rsa contains an isomorphic interface to the RSA algorithm for GopherJS
// and standard platforms.
package rsa

type RSA interface {
	GenerateKey(exportable bool) (*PrivateKey, error)
	Encrypt(pub *PublicKey, msg []byte) ([]byte, error)
}
