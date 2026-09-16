package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

//* Constructor */

type AESGCM struct {
	NameStr string
	DescStr string

	NonceSizeBytes int
	KeySizeBytes   int
	NewCipher      func(key []byte) (cipher.AEAD, error)
}

// newAESGCM initializes a new AESGCM instance that only uses the first keySizeBytes bytes of the provided crypto key.
func newAESGCM(keySizeBytes int) *AESGCM {
	return &AESGCM{
		NameStr: fmt.Sprintf("aesgcm%d", keySizeBytes*8),
		DescStr: fmt.Sprintf("symmetric %d-bit AES with GCM authentication", keySizeBytes*8),

		NonceSizeBytes: 12,
		KeySizeBytes:   keySizeBytes,
		NewCipher: func(key []byte) (cipher.AEAD, error) {
			cipherBlock, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}

			aeadCipher, err := cipher.NewGCM(cipherBlock)
			if err != nil {
				return nil, err
			}

			return aeadCipher, nil
		},
	}
}

func NewAESGCM128() *AESGCM {
	return newAESGCM(16)
}

func NewAESGCM192() *AESGCM {
	return newAESGCM(24)
}

func NewAESGCM256() *AESGCM {
	return newAESGCM(32)
}

//* Methods */

func (aead *AESGCM) Name() string {
	return aead.NameStr
}

func (aead *AESGCM) Description() string {
	return aead.DescStr
}

func (aead *AESGCM) NonceSize() int {
	return aead.NonceSizeBytes
}

func (aead *AESGCM) Encrypt(plainBytes []byte, key []byte) ([]byte, []byte, error) {
	// get cipher from key
	aeadCipher, err := aead.NewCipher(key[:aead.KeySizeBytes])
	if err != nil {
		return nil, nil, err
	}

	// generate random nonce
	nonce := make([]byte, aead.NonceSizeBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	// return (nonce, ciphertext)
	return nonce, aeadCipher.Seal(nil, nonce, plainBytes, nil), nil
}

func (aead *AESGCM) Decrypt(nonce []byte, cipherBytes []byte, key []byte) ([]byte, error) {
	// get cipher from key
	aeadCipher, err := aead.NewCipher(key[:aead.KeySizeBytes])
	if err != nil {
		return nil, err
	}

	// decrypt data
	plainBytes, err := aeadCipher.Open(nil, nonce, cipherBytes, nil)
	if err != nil {
		return nil, err
	}

	// return (plaintext)
	return plainBytes, nil
}
