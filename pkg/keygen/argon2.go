package keygen

import (
	"golang.org/x/crypto/argon2"
)

type Argon2Keygen struct {
	NameStr string
	DescStr string

	Time    uint32
	Memory  uint32
	Threads uint8
	KeySize uint32
}

func NewArgon2Keygen() *Argon2Keygen {
	return &Argon2Keygen{
		NameStr: "argon2",
		DescStr: "argon2 key derivation function",

		Time:    1,         // number of passes over the memory
		Memory:  64 * 1024, // size of memory in KiB
		Threads: 4,         // CPU threads to use
		KeySize: 32,        // key size
	}
}

func (kg *Argon2Keygen) Name() string {
	return kg.NameStr
}

func (kg *Argon2Keygen) Description() string {
	return kg.DescStr
}

func (kg *Argon2Keygen) DeriveKey(psw string, salt []byte) ([]byte, error) {
	return argon2.IDKey([]byte(psw), salt, kg.Time, kg.Memory, kg.Threads, kg.KeySize), nil
}
