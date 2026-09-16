// Package pswgen generates random passwords and defines the character set that Cloak uses in passwords.
package pswgen

import (
	"crypto/rand"
	"math/big"
	"strings"
)

const (
	AllowedUppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" // AllowedUppercase are the uppercase letters allowed in passwords.
	AllowedLowercase = "abcdefghijklmnopqrstuvwxyz" // AllowedLowercase are the lowercase letters allowed in passwords.
	AllowedNumbers   = "0123456789"                 // AllowedNumbers are the numbers allowed in passwords.
	AllowedSymbols   = "!@#%^*-_=+.,?"              // AllowedSymbols are the special characters allowed in passwords, chosen to be safe for shells and config files.

	AllowedCharset = AllowedUppercase + AllowedLowercase + AllowedNumbers + AllowedSymbols // Charset is the set of characters allowed in passwords, including ASCII letters, digits, and [AllowedSymbols].

	MinPasswordLength = 8 // MinPasswordLength is the minimum number of characters in a password.
)

// GenerateRandomPassword returns a random password of the given length, drawn uniformly from the [AllowedCharset]. It panics if a negative password length is provided.
func GenerateRandomPassword(length int) (string, error) {
	max := big.NewInt(int64(len(AllowedCharset)))
	buf := make([]byte, length)
	for i := range length {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		buf[i] = AllowedCharset[n.Int64()]
	}

	return string(buf), nil
}

// ValidatePassword reports whether psw is at least [MinPasswordLength] characters long and uses only characters from the [AllowedCharset].
func ValidatePassword(psw string) bool {
	// check password length
	if len(psw) < MinPasswordLength {
		return false
	}

	// check password content
	for _, r := range psw {
		if !strings.ContainsRune(AllowedCharset, r) {
			return false
		}
	}

	return true
}
