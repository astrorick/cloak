package algos

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/astrorick/cloak/pkg/keygen"
	"golang.org/x/crypto/chacha20poly1305"
)

type AEAD struct {
	Name        string
	Description string

	SaltSize  int
	NonceSize int

	Keygen  keygen.Keygen
	Factory func(key []byte) (cipher.AEAD, error)
}

//* AES Family with GCM Authentication */

func newAESGCM(keySizeBytes uint8) *AEAD {
	return &AEAD{
		Name:        fmt.Sprintf("aesgcm%d", keySizeBytes),
		Description: fmt.Sprintf("symmetric AES encryption with GCM authentication (%d-bit)", keySizeBytes*8),

		SaltSize:  16,
		NonceSize: 12,

		Keygen: &keygen.ArgonKeygen{
			Time:    8,
			Memory:  128 * 1024,
			Threads: 4,
			KeySize: uint32(keySizeBytes),
		},
		Factory: func(key []byte) (cipher.AEAD, error) {
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}

			return cipher.NewGCM(block)
		},
	}
}

func NewAESGCM128() *AEAD {
	return newAESGCM(16)
}

func NewAESGCM192() *AEAD {
	return newAESGCM(24)
}

func NewAESGCM256() *AEAD {
	return newAESGCM(32)
}

//* ChaCha20 Family with Poly1305 Authentication */

func NewChaCha20Poly1305() *AEAD {
	return &AEAD{
		Name:        "chacha20poly1305",
		Description: "symmetric ChaCha20 encryption with Poly1305 authentication",

		SaltSize:  16,
		NonceSize: 12,

		Keygen: &keygen.ArgonKeygen{
			Time:    8,
			Memory:  128 * 1024,
			Threads: 4,
			KeySize: 32,
		},
		Factory: func(key []byte) (cipher.AEAD, error) {
			aead, err := chacha20poly1305.New(key)
			if err != nil {
				return nil, err
			}

			return aead, nil
		},
	}
}

//* Generic Encryption and Decryption Methods */

func (aead *AEAD) Name() string {
	return aead.Name
}

func (aead *AEAD) Description() string {
	return aead.Description
}

func (aead *AEAD) Encrypt(input io.Reader, output io.Writer, psw string) error {
	// generate random salt for key derivation
	salt := make([]byte, aead.SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("error generating random salt: %w", err)
	}

	// derive encryption key from psw and salt
	key, err := aead.Keygen.DeriveKey(psw, salt)
	if err != nil {
		return fmt.Errorf("error generating encryption key: %w", err)
	}

	// generate random nonce
	nonce := make([]byte, aead.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("error generating random nonce: %w", err)
	}

	// get cipher
	cipherAEAD, err := aead.Factory(key)
	if err != nil {
		return fmt.Errorf("error getting aead: %w", err)
	}

	// read source file
	plainData, err := io.ReadAll(input)
	if err != nil {
		return fmt.Errorf("error reading input file: %w", err)
	}

	// encrypt data
	cipherData := cipherAEAD.Seal(nil, nonce, plainData, nil)

	// write salt + nonce + ciphertext to output file
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

func (aead *AEAD) Decrypt(input io.Reader, output io.Writer, psw string) error {
	// read header (salt + nonce) from input file
	header := make([]byte, aead.SaltSize+aead.NonceSize)
	if _, err := io.ReadFull(input, header); err != nil {
		return fmt.Errorf("error reading header from input file: %w", err)
	}
	salt := header[:aead.SaltSize]
	nonce := header[aead.SaltSize:]

	// derive encryption key from psw and salt
	key, err := aead.Keygen.DeriveKey(psw, salt)
	if err != nil {
		return fmt.Errorf("error generating decryption key: %w", err)
	}

	// get cipher
	cipherAEAD, err := aead.Factory(key)
	if err != nil {
		return fmt.Errorf("error getting aead: %w", err)
	}

	// read the remaining input file (cipher data)
	cipherData, err := io.ReadAll(input)
	if err != nil {
		return fmt.Errorf("error reading input file: %w", err)
	}

	// decrypt data
	plainData, err := cipherAEAD.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return fmt.Errorf("decryption failed or data corrupted: %w", err)
	}

	// write decrypted data to output file
	if _, err := output.Write(plainData); err != nil {
		return fmt.Errorf("error writing decrypted data to output file: %w", err)
	}

	return nil
}
