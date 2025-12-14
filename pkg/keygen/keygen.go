package keygen

import (
	"crypto/rand"
)

// GenerateKey produces a random key for file encryption/decryption.
func GenerateKey() ([]byte, error) {
	// make a completely random key (no password needed)
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	return key, nil
}

// KeyDer is the interface that each implemented key derivation method must satisfy.
type KeyDer interface {
	Name() string
	Description() string

	DeriveKey(psw string, salt []byte) ([]byte, error)
}

// Implemented maps implemented methods to their internal name.
var Implemented = map[string]KeyDer{
	"argon2": NewArgon2(),
	"pbkdf2": NewPBKDF2(),
}

// Default represents the default key derivation function used when no flag is passed.
var Default = Implemented["argon2"]
