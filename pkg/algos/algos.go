// Package algos provides the encryption algorithms available in Cloak.
package algos

import (
	"slices"

	"github.com/astrorick/cloak/pkg/algos/aead"
)

// CryptoAlgorithm is an authenticated encryption algorithm. It uses only as many leading bytes of the key as it needs.
type CryptoAlgorithm interface {
	Name() string        // Name returns the algorithm's CLI name, which must match its key in [ImplementedAlgos].
	Description() string // Description returns a short description of the algorithm.
	NonceSize() int      // NonceSize returns the length in bytes of the nonce produced by Encrypt and expected by Decrypt.

	Encrypt(plainBytes []byte, key []byte) (nonce []byte, cipherBytes []byte, err error) // Encrypt returns a fresh random nonce and the ciphertext.
	Decrypt(nonce []byte, cipherBytes []byte, key []byte) (plainBytes []byte, err error) // Decrypt reverses Encrypt.
}

// ImplementedAlgos maps CLI names to the available encryption algorithms.
var ImplementedAlgos = map[string]CryptoAlgorithm{
	//* Advanced Encryption Standard (AES) Family */
	"aesgcm128": aead.NewAESGCM128(),
	"aesgcm192": aead.NewAESGCM192(),
	"aesgcm256": aead.NewAESGCM256(),

	//* ChaCha20 Family */
	"chacha20poly1305": aead.NewChaCha20Poly1305(),
}

// DefaultAlgo is the encryption algorithm used when none is specified.
var DefaultAlgo = ImplementedAlgos["aesgcm256"]

// GetImplementedAlgoNames returns the sorted names of the algorithms in [ImplementedAlgos].
func GetImplementedAlgoNames() []string {
	algoNames := make([]string, 0, len(ImplementedAlgos))
	for algoName := range ImplementedAlgos {
		algoNames = append(algoNames, algoName)
	}

	slices.Sort(algoNames)

	return algoNames
}
