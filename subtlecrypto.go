// +build js

package subtlecrypto

import (
	"errors"

	"github.com/gopherjs/gopherjs/js"
)

// Uses
type Use string

var (
	ENCRYPT     Use = "encrypt"
	DECRYPT     Use = "decrypt"
	SIGN        Use = "sign"
	VERIFY      Use = "verify"
	DERIVE_KEY  Use = "deriveKey"
	DERIVE_BITS Use = "deriveBits"
	WRAP_KEY    Use = "wrapKey"
	UNWRAP_KEY  Use = "unwrapKey"
)

// Promise wraps a JS Promise/A+ object
type Promise struct {
	*js.Object
}

// Then wraps an asynchronous call to the then method
// of a promise, returning the success or failure as
// a return pair.
func (p *Promise) Then() (*js.Object, error) {
	success := make(chan *js.Object)
	failure := make(chan *js.Object)
	p.Call("then", func(o *js.Object) { success <- o }, func(o *js.Object) { failure <- o })

	select {
	case o := <-success:
		return o, nil
	case o := <-failure:
		return nil, &js.Error{o}
	}
}

type subtlecrypto struct {
	*js.Object
}

func (s *subtlecrypto) CallAsync(method string, args ...interface{}) (*js.Object, error) {
	p := &Promise{s.Call(method, args...)}
	return p.Then()
}

var subtle *subtlecrypto

func init() {
	// browser
	crypto := js.Global.Get("crypto")
	if crypto == js.Undefined {
		crypto = js.Global.Get("msCrypto")
	}
	if crypto != js.Undefined {
		subtlejs := crypto.Get("subtle")
		if subtlejs == js.Undefined {
			subtlejs = crypto.Get("webkitSubtle")
		}
		if subtlejs != js.Undefined {
			subtle = &subtlecrypto{subtlejs}
			return
		}
	}

	// TODO nodejs

	panic(errors.New("crypto/subtle not available in this environment"))
}
