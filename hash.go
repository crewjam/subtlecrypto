package subtlecrypto

import (
	"github.com/gopherjs/gopherjs/js"
)

// Hash algorithms
type HashAlgorithm struct {
	*js.Object
	Name string `js:"name"`
}

func hashForName(name string) *HashAlgorithm {
	a := &HashAlgorithm{Object: js.Global.Get("Object").New()}
	a.Name = name
	return a
}

var (
	SHA_1   = hashForName("SHA-1")
	SHA_256 = hashForName("SHA-256")
	SHA_384 = hashForName("SHA-384")
	SHA_512 = hashForName("SHA-512")
)
