// Package keygen generates random keys and derives keys from passwords.
package keygen

import (
	"crypto/rand"
	"slices"

	"github.com/astrorick/cloak/pkg/keygen/methods"
)

// GenerateRandomKey returns a random 64-byte key.
func GenerateRandomKey() ([]byte, error) {
	// make a completely random 64 byte key (no password needed here)
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	return key, nil
}

// KeyDerMethod is a password-based key derivation function.
type KeyDerMethod interface {
	Name() string        // Name returns the method's CLI name, which must match its key in [ImplementedMethods].
	Description() string // Description returns a short description of the method.

	DeriveKey(psw string, salt []byte) ([]byte, error) // DeriveKey derives a key from psw and salt.
}

// ImplementedMethods maps CLI names to the available key derivation methods.
var ImplementedMethods = map[string]KeyDerMethod{
	"argon2": methods.NewArgon2(),
	"pbkdf2": methods.NewPBKDF2(),
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
