package algos

import (
	"crypto/pbkdf2"
	"crypto/sha512"
	"io"
)

type AES256 struct {
	name    string
	numIter int
	keySize int
}

func NewAES256() *AES256 {
	return &AES256{
		name:    "aes256",
		numIter: 2 << 16,
		keySize: 32,
	}
}

func (algo *AES256) Name() string {
	return algo.name
}

func (algo *AES256) DeriveKey(psw string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha512.New, psw, salt, algo.numIter, algo.keySize)
}

func (algo *AES256) Encrypt(input io.Reader, output io.Writer, key []byte) error {
	return nil
}

func (algo *AES256) Decrypt(input io.Reader, output io.Writer, key []byte) error {
	return nil
}
