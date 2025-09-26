package algos

import "io"

// CryptoAlgorithm is the interface each implemented crypto algorithm must satisfy.
type CryptoAlgorithm interface {
	Name() string
	Description() string
	Encrypt(input io.Reader, output io.Writer, psw string) error
	Decrypt(input io.Reader, output io.Writer, psw string) error
}

var Implemented = map[string]CryptoAlgorithm{
	//* Advanced Encryption Standard (AES) Family */
	"aesgcm128": NewAESGCM128(),
	"aesgcm192": NewAESGCM192(),
	"aesgcm256": NewAESGCM256(),

	//* ChaCha20 Family */
	"chacha20poly1305": NewChaCha20Poly1305(),
}

var Default = Implemented["aesgcm256"]
