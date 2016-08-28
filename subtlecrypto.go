// +build js

//go:generate gopherjs test -v --short --bench=. -c

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

//   @override
//   Future<String> decryptString(BrowserKey key, EncryptedMessage message) {
//     return decryptBuffer(key, message).then((buffer) => new Utf8Decoder().convert(buffer));
//   }

//   @override
//   Future<Uint8List> decryptBuffer(BrowserKey key, EncryptedMessage message) {
//     Completer<Uint8List> completer = new Completer();

//     var algo = AES_CBC;

//     JsObject promise = context['Kevalin'].callMethod('decrypt', [
//       algo,
//       message.iv,
//       key._key,
//       message.bytes
//     ]);

//     promise.callMethod('then', [completer.complete, completer.completeError]);
//     return completer.future;
//   }

//   @override
//   Future<EncryptedMessage> encryptString(BrowserKey key, String cleartext) {
//     var buffer = new Utf8Encoder().convert(cleartext);
//     return encryptBuffer(key, buffer);
//   }

//   @override
//   Future<EncryptedMessage> encryptBuffer(BrowserKey key, List<int> buffer) {
//     Completer<EncryptedMessage> completer = new Completer();

//     var algo = AES_CBC;
//     var iv = new Uint8List(16);
//     html.window.crypto.getRandomValues(iv);

//     JsObject promise = _kevalin.callMethod('encrypt', [
//       algo,
//       iv,
//       key._key,
//       buffer
//     ]);

//     promise.callMethod('then', [
//         (Uint8List buffer) => completer.complete(new EncryptedMessage()
//           .. iv = iv
//           .. bytes = buffer),
//         completer.completeError]);
//     return completer.future;
//   }

//   @override
//   Future<CryptoKeyPair> generateWrappingKey() {
//     var algo = RSA_OAEP;
//     var uses = [WRAP_KEY, UNWRAP_KEY];

//     print("Generating $algo key for $uses");
//     Completer<CryptoKeyPair> completer = new Completer();

//     JsObject promise = _kevalin.callMethod('generateKey', [
//       new JsObject.jsify({
//         'name': algo,
//         'modulusLength': 2048,
//         'publicExponent': new BigInteger("65537").toByteArray(),
//         'hash': {'name': SHA_512}
//       }),
//       true,
//       new JsObject.jsify(uses)
//     ]);

//     promise.callMethod('then', [(JsObject key) => completer.complete(new BrowserKeyPair(key)), completer.completeError]);
//     return completer.future;
//   }

//   @override
//   Future<CryptoKey> import(Key key) {
//     // Decode JSON JWK key
//     JsObject keyData;
//     var jwk = UTF8.decode(key.key);
//     try {
//       keyData = context['JSON'].callMethod('parse', [jwk]);
//     }
//     catch (e) {
//       print("Unable to parse key data: " + jwk);
//       return null;
//     }

//     // Get algorithm name
//     JsObject algo;
//     switch (keyData['alg']) {
//       case 'RSA-OAEP-512':
//         algo = new JsObject.jsify({
//           'name': RSA_OAEP,
//           'hash': {'name': SHA_512}
//         });
//         break;
//       case 'RS512':
//         algo = new JsObject.jsify({
//           'name': RSASSA_PKCS1_v1_5,
//           'hash': {'name': SHA_512}
//         });
//         break;
//       default:
//         throw "Unrecognised algorithm in key: ${keyData['alg']}";
//     }

//     List<String> usage = keyData['key_ops'];

//     Completer<CryptoKeyPair> completer = new Completer();
//     JsObject promise = _crypto.callMethod('importKey', [
//       "jwk",
//       keyData,
//       algo,
//       true,
//       usage
//     ]);

//     promise.callMethod('then', [(JsObject key) => completer.complete(new BrowserKey(key)), completer.completeError]);
//     return completer.future;
//   }

//   @override
//   Future<Uint8List> wrapKey(BrowserKey key, BrowserKey wrappingKey) {
//     Completer<Key> completer = new Completer();

//     var algo = RSA_OAEP;

//     JsObject promise = _kevalin.callMethod('wrapKey', [
//       "raw",
//       key._key,
//       wrappingKey._key,
//       new JsObject.jsify({'name': algo})
//     ]);

//     promise.callMethod('then', [
//         (Uint8List buffer) {
//           completer.complete(buffer);
//         },
//         completer.completeError]);
//     return completer.future;
//   }

//   @override
//   Future<CryptoKey> unwrapKey(Uint8List buffer, BrowserKey wrappingKey) {
//     Completer<CryptoKey> completer = new Completer();

//     var algo = RSA_OAEP;

//     var wrappedAlgo = AES_CBC;
//     var length = 256;
//     List<String> usage = [ENCRYPT, DECRYPT];

//     // Perform the unwrapping
//     JsObject promise = _crypto.callMethod('unwrapKey', [
//       "raw",
//       buffer,
//       wrappingKey._key,
//       new JsObject.jsify({'name': algo, 'hash': {'name': SHA_256}}),
//       new JsObject.jsify({'name': wrappedAlgo, 'length': length}),
//       true, // Extractable
//       new JsObject.jsify(usage)
//     ]);

//     // Return result;
//     promise.callMethod('then', [
//       (JsObject unwrappedKey) => completer.complete(
//         new BrowserKey(unwrappedKey)
//       ),
//       completer.completeError]);
//     return completer.future;
//   }

//   @override
//   Future<Signature> sign(BrowserKey signingKey, List<int> buffer) {
//     Completer<Signature> completer = new Completer();

//     var algo = RSASSA_PKCS1_v1_5;
//     var signingAlgo = new JsObject.jsify({
//       'name': algo,
//       'hash': {'name': SHA_512}
//     });

//     JsObject promise = _kevalin.callMethod('sign', [signingAlgo, signingKey._key, buffer]);

//     // Return result;
//     promise.callMethod('then', [
//       (Uint8List signature) => completer.complete(
//          new Signature()
//           .. signature = signature
//       ),
//       completer.completeError]);

//     return completer.future;
//   }

//   @override
//   Future<bool> verify(BrowserKey signingKey, List<int> buffer, Signature signature) {
//     Completer<bool> completer = new Completer();

//     var algo = RSASSA_PKCS1_v1_5;
//     var signingAlgo = new JsObject.jsify({
//       'name': algo,
//       'hash': {'name': SHA_512}
//     });

//     //                                               algo, key, signature, text2verify
//     JsObject promise = _crypto.callMethod('verify', [signingAlgo, signingKey._key, signature.signature, buffer]);

//     // Return result;
//     promise.callMethod('then', [
//       completer.complete,
//       completer.completeError]);

//     return completer.future;
//   }
