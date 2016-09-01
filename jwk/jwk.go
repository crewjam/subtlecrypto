// +build !js

// Package jwk provides types for handling JSON Web Key objects
package jwk

// Key represents the contents of a JSON Web Key according to
// https://tools.ietf.org/html/rfc7517
//
// TODO Certificates and protected headers
type Key struct {
	// General params
	KeyType string   `json:"kty"`
	Use     string   `json:"use"`
	KeyID   string   `json:"kid"`
	Ext     bool     `json:"ext"`
	KeyOps  []string `json:"key_ops"`

	// Symmetric key params
	K string `json:"k"`

	// Common key params
	D string `json:"d"` // Used by EC and RSA

	// EC params
	Curve string `json:"crv"`
	X     string `json:"x"`
	Y     string `json:"y"`

	// RSA params
	N         string `json:"n"`
	E         string `json:"e"`
	P         string `json:"p"`
	Q         string `json:"q"`
	DP        string `json:"dp"`
	DQ        string `json:"dq"`
	QI        string `json:"qi"`
	Algorithm string `json:"alg"`
}
