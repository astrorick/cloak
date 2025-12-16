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
	NameStr string
	DescStr string

	SaltSize  int
	NonceSize int

	KeyDerMethod keygen.KeyDerMethod
	NewCipher    func(key []byte) (cipher.AEAD, error)
}

//* AES Family with GCM Authentication */

func newAESGCM(keySizeBytes int) *AEAD {
	return &AEAD{
		NameStr: fmt.Sprintf("aesgcm%d", keySizeBytes*8),
		DescStr: fmt.Sprintf("symmetric AES with GCM authentication (%d-bit)", keySizeBytes*8),

		SaltSize:  16,
		NonceSize: 12,

		KeyDerMethod: &keygen.Argon2{
			Time:    8,
			Memory:  128 * 1024,
			Threads: 4,
			KeySize: uint32(keySizeBytes),
		},
		NewCipher: func(key []byte) (cipher.AEAD, error) {
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}

			aeadCipher, err := cipher.NewGCM(block)
			if err != nil {
				return nil, err
			}

			return aeadCipher, nil
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
		NameStr: "chacha20poly1305",
		DescStr: "symmetric ChaCha20 with Poly1305 authentication ",

		SaltSize:  16,
		NonceSize: 12,

		KeyDerMethod: &keygen.Argon2{
			Time:    8,
			Memory:  128 * 1024,
			Threads: 4,
			KeySize: 32,
		},
		NewCipher: func(key []byte) (cipher.AEAD, error) {
			aeadCipher, err := chacha20poly1305.New(key)
			if err != nil {
				return nil, err
			}

			return aeadCipher, nil
		},
	}
}

//* Generic Encryption and Decryption Methods */

func (aead *AEAD) Name() string {
	return aead.NameStr
}

func (aead *AEAD) Description() string {
	return aead.DescStr
}

func (aead *AEAD) EncryptWithPsw(input io.Reader, output io.Writer, psw string) error {
	// generate random salt for key derivation
	salt := make([]byte, aead.SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("error generating random salt: %w", err)
	}

	// derive encryption key from psw and salt
	key, err := aead.KeyDerMethod.DeriveKey(psw, salt)
	if err != nil {
		return fmt.Errorf("error generating encryption key: %w", err)
	}

	// generate random nonce
	nonce := make([]byte, aead.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("error generating random nonce: %w", err)
	}

	// get cipher from key
	aeadCipher, err := aead.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error creating cipher: %w", err)
	}

	// read entire source file
	plainBytes, err := io.ReadAll(input)
	if err != nil {
		return fmt.Errorf("error reading input file: %w", err)
	}

	// encrypt data
	cipherBytes := aeadCipher.Seal(nil, nonce, plainBytes, nil)

	// write salt + nonce + ciphertext to output file
	if _, err := output.Write(salt); err != nil {
		return fmt.Errorf("error writing salt to output file: %w", err)
	}
	if _, err := output.Write(nonce); err != nil {
		return fmt.Errorf("error writing nonce to output file: %w", err)
	}
	if _, err := output.Write(cipherBytes); err != nil {
		return fmt.Errorf("error writing ciphertext to output file: %w", err)
	}

	return nil
}

func (aead *AEAD) DecryptWithPsw(input io.Reader, output io.Writer, psw string) error {
	// read salt from input file
	salt := make([]byte, aead.SaltSize)
	if _, err := io.ReadFull(input, salt); err != nil {
		return fmt.Errorf("error reading salt from input file: %w", err)
	}

	// derive decryption key from psw and salt
	key, err := aead.KeyDerMethod.DeriveKey(psw, salt)
	if err != nil {
		return fmt.Errorf("error generating decryption key: %w", err)
	}

	// read nonce from input file
	nonce := make([]byte, aead.NonceSize)
	if _, err := io.ReadFull(input, nonce); err != nil {
		return fmt.Errorf("error reading nonce from input file: %w", err)
	}

	// get cipher from key
	aeadCipher, err := aead.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error creating cipher: %w", err)
	}

	// read the remaining input file (cipher bytes)
	cipherBytes, err := io.ReadAll(input)
	if err != nil {
		return fmt.Errorf("error reading input file: %w", err)
	}

	// decrypt data
	plainBytes, err := aeadCipher.Open(nil, nonce, cipherBytes, nil)
	if err != nil {
		return fmt.Errorf("decryption failed or data corrupted: %w", err)
	}

	// write decrypted data to output file
	if _, err := output.Write(plainBytes); err != nil {
		return fmt.Errorf("error writing decrypted data to output file: %w", err)
	}

	return nil
}
