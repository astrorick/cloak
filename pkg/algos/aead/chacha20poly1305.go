package aead

import (
	"crypto/cipher"
	"crypto/rand"

	"golang.org/x/crypto/chacha20poly1305"
)

//* Constructor */

type ChaCha20Poly1305 struct {
	NameStr string
	DescStr string

	NonceSizeBytes int
	KeySizeBytes   int
	NewCipher      func(key []byte) (cipher.AEAD, error)
}

// NewChaCha20Poly1305 initializes a new ChaCha20Poly1305 instance that only uses the first keySizeBytes bytes of the provided crypto key.
func NewChaCha20Poly1305() *ChaCha20Poly1305 {
	return &ChaCha20Poly1305{
		NameStr: "chacha20poly1305",
		DescStr: "symmetric ChaCha20 with Poly1305 authentication",

		NonceSizeBytes: 12,
		KeySizeBytes:   32,
		NewCipher: func(key []byte) (cipher.AEAD, error) {
			aeadCipher, err := chacha20poly1305.New(key)
			if err != nil {
				return nil, err
			}

			return aeadCipher, nil
		},
	}
}

//* Methods */

func (aead *ChaCha20Poly1305) Name() string {
	return aead.NameStr
}

func (aead *ChaCha20Poly1305) Description() string {
	return aead.DescStr
}

func (aead *ChaCha20Poly1305) NonceSize() int {
	return aead.NonceSizeBytes
}

func (aead *ChaCha20Poly1305) Encrypt(plainBytes []byte, key []byte) ([]byte, []byte, error) {
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

func (aead *ChaCha20Poly1305) Decrypt(nonce []byte, cipherBytes []byte, key []byte) ([]byte, error) {
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
