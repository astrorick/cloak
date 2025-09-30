package algos

import (
	"io"
	"slices"
)

// CryptoAlgorithm is the interface that each implemented crypto algorithm must satisfy.
type CryptoAlgorithm interface {
	Name() string
	Description() string

	EncryptWithPsw(input io.Reader, output io.Writer, psw string) error
	DecryptWithPsw(input io.Reader, output io.Writer, psw string) error
}

// Implemented maps implemented algorithms to their internal name.
var Implemented = map[string]CryptoAlgorithm{
	//* Advanced Encryption Standard (AES) Family */
	"aesgcm128": NewAESGCM128(),
	"aesgcm192": NewAESGCM192(),
	"aesgcm256": NewAESGCM256(),

	//* ChaCha20 Family */
	"chacha20poly1305": NewChaCha20Poly1305(),
}

// Default represents the default crypto algorithm used when no flag is passed.
var Default = Implemented["aesgcm256"]

// GetImplementedAlgoNames returns a strings slice with the names of implemented algorithms.
func GetImplementedAlgoNames() []string {
	algoNames := make([]string, 0, len(Implemented))
	for algoName := range Implemented {
		algoNames = append(algoNames, algoName)
	}

	slices.Sort(algoNames)

	return algoNames
}
