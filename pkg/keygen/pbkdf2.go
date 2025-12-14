package keygen

import (
	"crypto/pbkdf2"
	"crypto/sha512"
	"hash"
)

type PBKDF2KeyDer struct {
	NameStr string
	DescStr string

	Hash    func() hash.Hash
	Iter    int
	KeySize int
}

func NewPBKDF2() *PBKDF2KeyDer {
	return &PBKDF2KeyDer{
		NameStr: "pbkdf2",
		DescStr: "password-based key derivation function 2",

		Hash:    sha512.New, // hasing function for key derivation
		Iter:    100_000,    // number of iterations
		KeySize: 32,         // key size
	}
}

func (kg *PBKDF2KeyDer) Name() string {
	return kg.NameStr
}

func (kg *PBKDF2KeyDer) Description() string {
	return kg.DescStr
}

func (kg *PBKDF2KeyDer) DeriveKey(psw string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(kg.Hash, psw, salt, kg.Iter, kg.KeySize)
}
