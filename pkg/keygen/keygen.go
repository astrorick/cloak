// Package keygen generates random keys and derives keys from passwords.
package keygen

import (
	"crypto/rand"
	"slices"

	"github.com/astrorick/cloak/pkg/keygen/methods"
)

// StandardKeySizeBytes is the size in bytes of every key handed to the crypto algorithms, whether randomly generated or derived from a password.
const StandardKeySizeBytes = 64

// GenerateRandomKey returns a random key of size [StandardKeySizeBytes] for key-based operations.
func GenerateRandomKey() ([]byte, error) {
	// make a completely random key (no password needed here)
	key := make([]byte, StandardKeySizeBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	return key, nil
}

// KeyDerMethod is a password-based key derivation function.
type KeyDerMethod interface {
	Name() string        // Name returns the method's CLI name, which must match its key in [ImplementedMethods].
	Description() string // Description returns a short description of the method.

	DeriveKey(psw string, salt []byte) ([]byte, error) // DeriveKey derives a key of size [StandardKeySizeBytes] from password and salt.
}

// ImplementedMethods maps CLI names to the available key derivation methods.
var ImplementedMethods = map[string]KeyDerMethod{
	"argon2": methods.NewArgon2(StandardKeySizeBytes),
	"pbkdf2": methods.NewPBKDF2(StandardKeySizeBytes),
}

// DefaultMethod is the key derivation method used when none is specified.
var DefaultMethod = ImplementedMethods["argon2"]

// GetImplementedMethodNames returns the sorted names of the methods in [ImplementedMethods].
func GetImplementedMethodNames() []string {
	methodNames := make([]string, 0, len(ImplementedMethods))
	for methodName := range ImplementedMethods {
		methodNames = append(methodNames, methodName)
	}

	slices.Sort(methodNames)

	return methodNames
}
