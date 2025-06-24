package algos

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

type ChaCha20Poly1305 struct {
	name string

	saltSize  int
	nonceSize int

	keySize     int
	keyHashIter int
}

func NewChaCha20Poly1305() *ChaCha20Poly1305 {
	return &ChaCha20Poly1305{
		name: "chacha20poly1305", // algorithm name

		saltSize:  16, // size of salt used for key derivation
		nonceSize: 12, // size of nonce to be used during encryption / decryption

		keySize:     32,      // size of encryption / decryption key
		keyHashIter: 2 << 16, // number of hashes for key derivation
	}
}

func (algo *ChaCha20Poly1305) Name() string {
	return algo.name
}

func (algo *ChaCha20Poly1305) Seal(input io.Reader, output io.Writer, psw string) error {
	// read source file
	plainData, err := io.ReadAll(input)
	if err != nil {
		return fmt.Errorf("error reading input file: %w", err)
	}

	// generate random salt for key derivation
	salt := make([]byte, algo.saltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("error generating random salt: %w", err)
	}

	// derive encryption key from psw and salt
	key, err := algo.deriveKey(psw, salt)
	if err != nil {
		return fmt.Errorf("error generating encryption key: %w", err)
	}

	// generate random nonce
	nonce := make([]byte, algo.nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("error generating random nonce: %w", err)
	}

	// create AEAD with key
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return fmt.Errorf("error creating AEAD: %w", err)
	}

	// encrypt data
	cipherData := aead.Seal(nil, nonce, plainData, nil)

	// write salt + iv + ciphertext to output file
	if _, err := output.Write(salt); err != nil {
		return fmt.Errorf("error writing salt to output file: %w", err)
	}
	if _, err := output.Write(nonce); err != nil {
		return fmt.Errorf("error writing nonce to output file: %w", err)
	}
	if _, err := output.Write(cipherData); err != nil {
		return fmt.Errorf("error writing ciphertext to output file: %w", err)
	}

	return nil
}

func (algo *ChaCha20Poly1305) Unseal(input io.Reader, output io.Writer, psw string) error {
	// read salt from input file
	salt := make([]byte, algo.saltSize)
	if _, err := io.ReadFull(input, salt); err != nil {
		return fmt.Errorf("error reading salt from input file: %w", err)
	}

	// derive encryption key from psw and salt
	key, err := algo.deriveKey(psw, salt)
	if err != nil {
		return fmt.Errorf("error generating decryption key: %w", err)
	}

	// read nonce from input file
	nonce := make([]byte, algo.nonceSize)
	if _, err := io.ReadFull(input, nonce); err != nil {
		return fmt.Errorf("error reading nonce from input file: %w", err)
	}

	// read the remaining input file (cipher data)
	cipherData, err := io.ReadAll(input)
	if err != nil {
		return fmt.Errorf("error reading input file: %w", err)
	}

	// create AEAD with key
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return fmt.Errorf("error creating chacha20poly1305: %w", err)
	}

	// decrypt data
	plainData, err := aead.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return fmt.Errorf("decryption failed or data corrupted: %w", err)
	}

	// write decrypted data to output file
	if _, err := output.Write(plainData); err != nil {
		return fmt.Errorf("error writing decrypted data to output file: %w", err)
	}

	return nil
}

func (algo *ChaCha20Poly1305) deriveKey(psw string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha512.New, psw, salt, algo.keyHashIter, algo.keySize)
}
