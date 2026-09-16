package methods

import (
	"crypto/pbkdf2"
	"crypto/sha512"
	"hash"
)

// PBKDF2 derives keys with PBKDF2.
type PBKDF2 struct {
	NameStr string // name of the method
	DescStr string // method description

	Hash    func() hash.Hash // hash function for key derivation
	Iter    int              // number of iterations
	KeySize int              // derived key size in bytes (keygen.StandardKeySizeBytes)
}

// NewPBKDF2 returns a PBKDF2 with Cloak's default parameters that derives keys of keySize bytes.
func NewPBKDF2(keySize int) *PBKDF2 {
	return &PBKDF2{
		NameStr: "pbkdf2",
		DescStr: "password-based key derivation function 2",

		Hash:    sha512.New,
		Iter:    220_000, // OWASP minimum for PBKDF2-HMAC-SHA512 (Password Storage Cheat Sheet)
		KeySize: keySize,
	}
}

func (kg *PBKDF2) Name() string {
	return kg.NameStr
}

func (kg *PBKDF2) Description() string {
	return kg.DescStr
}

// DeriveKey derives a key of KeySize bytes from psw and salt.
func (kg *PBKDF2) DeriveKey(psw string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(kg.Hash, psw, salt, kg.Iter, kg.KeySize)
}
