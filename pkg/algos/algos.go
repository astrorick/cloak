package algos

import (
	"io"
	"slices"
)

// CryptoAlgorithm is the interface that each implemented crypto algorithm must satisfy.
type CryptoAlgorithm interface {
	Name() string        // name of the algorithm
	Description() string // algorithm description

	// EncryptWithKey(input io.Reader, output io.Writer, key []byte) error // encrypt using the crypto key provided by the user
	// DecryptWithKey(input io.Reader, output io.Writer, key []byte) error // decrypt using the crypto key provided by the user
	EncryptWithPsw(input io.Reader, output io.Writer, psw string) error // encrypt using the password provided by the user
	DecryptWithPsw(input io.Reader, output io.Writer, psw string) error // decrypt using the password provided by the user
}

// ImplementedAlgos maps implemented algorithms to their internal name.
var ImplementedAlgos = map[string]CryptoAlgorithm{
	//* Advanced Encryption Standard (AES) Family */
	"aesgcm128": NewAESGCM128(),
	"aesgcm192": NewAESGCM192(),
	"aesgcm256": NewAESGCM256(),

	//* ChaCha20 Family */
	"chacha20poly1305": NewChaCha20Poly1305(),
}

// DefaultAlgo represents the default crypto algorithm used when no flag is passed.
var DefaultAlgo = ImplementedAlgos["aesgcm256"]

// GetImplementedAlgoNames returns a strings slice with the names of implemented algorithms.
func GetImplementedAlgoNames() []string {
	algoNames := make([]string, 0, len(ImplementedAlgos))
	for algoName := range ImplementedAlgos {
		algoNames = append(algoNames, algoName)
	}

	slices.Sort(algoNames)

	return algoNames
}
