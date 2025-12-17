package algos

import (
	"slices"

	"github.com/astrorick/cloak/pkg/algos/aead"
)

// CryptoAlgorithm is the interface that each implemented crypto algorithm must satisfy.
type CryptoAlgorithm interface {
	Name() string        // name of the algorithm
	Description() string // algorithm description

	Encrypt(plainBytes []byte, key []byte) ([]byte, error)  // encrypt using key
	Decrypt(cipherBytes []byte, key []byte) ([]byte, error) // decrypt using key
}

// ImplementedAlgos maps implemented algorithms to their internal name.
var ImplementedAlgos = map[string]CryptoAlgorithm{
	//* Advanced Encryption Standard (AES) Family */
	"aesgcm128": aead.NewAESGCM128(),
	"aesgcm192": aead.NewAESGCM192(),
	"aesgcm256": aead.NewAESGCM256(),

	//* ChaCha20 Family */
	"chacha20poly1305": aead.NewChaCha20Poly1305(),
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
