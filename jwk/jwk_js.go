// +build js

package jwk

import (
	"github.com/gopherjs/gopherjs/js"
)

// Key represents the contents of a JSON Web Key according to
// https://tools.ietf.org/html/rfc7517
//
// TODO Certificates and protected headers
type Key struct {
	*js.Object

	// General params
	KeyType string   `js:"kty"`
	Use     string   `js:"use"`
	KeyID   string   `js:"kid"`
	Ext     bool     `js:"ext"`
	KeyOps  []string `js:"key_ops"`

	// Symmetric key params
	K string `js:"k"`

	// Common key params
	D string `js:"d"` // Used by EC and RSA

	// EC params
	Curve string `js:"crv"`
	X     string `js:"x"`
	Y     string `js:"y"`

	// RSA params
	N         string `js:"n"`
	E         string `js:"e"`
	P         string `js:"p"`
	Q         string `js:"q"`
	DP        string `js:"dp"`
	DQ        string `js:"dq"`
	QI        string `js:"qi"`
	Algorithm string `js:"alg"`
}

func New() *Key {
	return &Key{Object: js.Global.Get("Object").New()}
}
