package keygen

import (
	"crypto/pbkdf2"
	"crypto/sha512"
	"hash"
)

type PBKDF2 struct {
	NameStr string // name of the method
	DescStr string // method description

	Hash    func() hash.Hash // hasing function for key derivation
	Iter    int              // number of iterations
	KeySize int              // desired key size
}

func NewPBKDF2() *PBKDF2 {
	return &PBKDF2{
		NameStr: "pbkdf2",
		DescStr: "password-based key derivation function 2",

		Hash:    sha512.New,
		Iter:    100_000,
		KeySize: 64,
	}
}

func (kg *PBKDF2) Name() string {
	return kg.NameStr
}

func (kg *PBKDF2) Description() string {
	return kg.DescStr
}

func (kg *PBKDF2) DeriveKey(psw string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(kg.Hash, psw, salt, kg.Iter, kg.KeySize)
}
