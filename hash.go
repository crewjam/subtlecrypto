package subtlecrypto

var (
	SHA_256 = newHash("SHA-256")
	SHA_384 = newHash("SHA-384")
	SHA_512 = newHash("SHA-512")
)

// Discouraged Algorithms
var (
	SHA_1 = newHash("SHA-1")
)

type Hash struct {
	*Algorithm
}

func newHash(name string) *Hash {
	a := &Hash{newAlgorithm(name)}
	return a
}
