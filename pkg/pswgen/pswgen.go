// Package pswgen generates random passwords and defines the character set that Cloak uses in passwords.
package pswgen

import (
	"crypto/rand"
	"math/big"
)

// AllowedSymbols are the special characters allowed in passwords, chosen to be safe in shells and config files.
const AllowedSymbols = "!@#%^*-_=+.,?"

// Charset is the set of characters allowed in passwords, including ASCII letters, digits, and [AllowedSymbols].
const Charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyz" + "0123456789" + AllowedSymbols

// GenerateRandomPassword returns a random password of the given length, drawn uniformly from [Charset]. It panics if a negative password length is provided.
func GenerateRandomPassword(length int) (string, error) {
	max := big.NewInt(int64(len(Charset)))
	buf := make([]byte, length)
	for i := range length {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		buf[i] = Charset[n.Int64()]
	}

	return string(buf), nil
}
