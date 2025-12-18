package keygen

import (
	"crypto/rand"
	"slices"

	"github.com/astrorick/cloak/pkg/keygen/methods"
)

// GenerateRandomKey produces a randomly generated key of fixed size for file encryption/decryption.
func GenerateRandomKey() ([]byte, error) {
	// make a completely random 64 byte key (no password needed here)
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	return key, nil
}

// KeyDerMethod is the interface that each implemented key derivation method must satisfy.
type KeyDerMethod interface {
	Name() string        // name of the method
	Description() string // method description

	DeriveKey(psw string, salt []byte) ([]byte, error)
}

// ImplementedMethods maps implemented methods to their internal name.
var ImplementedMethods = map[string]KeyDerMethod{
	"argon2": methods.NewArgon2(),
	"pbkdf2": methods.NewPBKDF2(),
}

// DefaultMethod represents the default key derivation function used when no flag is passed.
var DefaultMethod = ImplementedMethods["argon2"]

// GetImplementedMethodNames returns a strings slice with the names of implemented key derivation methods.
func GetImplementedMethodNames() []string {
	methodNames := make([]string, 0, len(ImplementedMethods))
	for methodName := range ImplementedMethods {
		methodNames = append(methodNames, methodName)
	}

	slices.Sort(methodNames)

	return methodNames
}
