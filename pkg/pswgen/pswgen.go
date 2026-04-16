package pswgen

import (
	"crypto/rand"
	"math/big"
)

// GenerateRandomPassword produces a cryptographically random password of the given length, drawn uniformly from printable ASCII characters (0x21-0x7E), consistent with utils.ValidatePassword.
func GenerateRandomPassword(length int) (string, error) {
	// printable ASCII range: '!' (0x21) through '~' (0x7E), 94 characters total
	const first = 0x21
	const count = 0x7E - 0x21 + 1

	max := big.NewInt(int64(count))
	buf := make([]byte, length)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		buf[i] = byte(first + n.Int64())
	}

	return string(buf), nil
}
