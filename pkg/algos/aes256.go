package algos

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

type AES256 struct {
	name string

	saltSize  uint64
	nonceSize uint64

	keyTime    uint32
	keyMemory  uint32
	keyThreads uint8
	keySize    uint32
}

func NewAES256() *AES256 {
	return &AES256{
		name: "aes256", // algorithm name

		saltSize:  16, // size of salt used for key derivation
		nonceSize: 12, // size of nonce to be used during encryption / decryption

		keyTime:    8,          // number of passes over the memory
		keyMemory:  128 * 1024, // KiB of RAM to use during key derivation
		keyThreads: 4,          // CPU threads to use during key derivation
		keySize:    32,         // size of encryption / decryption key
	}
}

func (algo *AES256) Name() string {
	return algo.name
}

func (algo *AES256) Seal(input io.Reader, output io.Writer, psw string) error {
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

	// create AES cipher with key
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error creating AES cipher block: %w", err)
	}

	// wrap cipher in GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("error wrapping cipher block in GCM: %w", err)
	}

	// encrypt data
	cipherData := aesgcm.Seal(nil, nonce, plainData, nil)

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

func (algo *AES256) Unseal(input io.Reader, output io.Writer, psw string) error {
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

	// create AES cipher with key
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error creating AES cipher block: %w", err)
	}

	// wrap cipher in GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("error wrapping cipher block in GCM: %w", err)
	}

	// decrypt data
	plainData, err := aesgcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return fmt.Errorf("decryption failed or data corrupted: %w", err)
	}

	// write decrypted data to output file
	if _, err := output.Write(plainData); err != nil {
		return fmt.Errorf("error writing decrypted data to output file: %w", err)
	}

	return nil
}

func (algo *AES256) deriveKey(psw string, salt []byte) ([]byte, error) {
	return argon2.IDKey([]byte(psw), salt, algo.keyTime, algo.keyMemory, algo.keyThreads, algo.keySize), nil
}
