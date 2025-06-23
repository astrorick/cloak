package algos

import (
	"crypto/pbkdf2"
	"crypto/sha512"
	"io"
)

type AES128 struct {
	name    string
	numIter int
	keySize int
}

func NewAES128() *AES128 {
	return &AES128{
		name:    "aes128",
		numIter: 2 << 16,
		keySize: 16,
	}
}

func (algo *AES128) Name() string {
	return algo.name
}

func (algo *AES128) DeriveKey(psw string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha512.New, psw, salt, algo.numIter, algo.keySize)
}

func (algo *AES128) Encrypt(input io.Reader, output io.Writer, key []byte) error {
	return nil
}

func (algo *AES128) Decrypt(input io.Reader, output io.Writer, key []byte) error {
	return nil
}
