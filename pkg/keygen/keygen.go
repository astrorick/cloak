package keygen

import (
	"crypto/pbkdf2"
	"hash"

	"golang.org/x/crypto/argon2"
)

type Keygen interface {
	DeriveKey(psw string, salt []byte) ([]byte, error)
}

//* PBKDF Family */

type PBKDFKeygen struct {
	Hash    func() hash.Hash
	Iter    int
	KeySize int
}

func (kg *PBKDFKeygen) DeriveKey(psw string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(kg.Hash, psw, salt, kg.Iter, kg.KeySize)
}

//* Argon Family */

type ArgonKeygen struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeySize uint32
}

func (kg *ArgonKeygen) DeriveKey(psw string, salt []byte) ([]byte, error) {
	return argon2.IDKey([]byte(psw), salt, kg.Time, kg.Memory, kg.Threads, kg.KeySize), nil
}
