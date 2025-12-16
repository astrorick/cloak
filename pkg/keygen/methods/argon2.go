package methods

import (
	"golang.org/x/crypto/argon2"
)

type Argon2 struct {
	NameStr string // name of the method
	DescStr string // method description

	Time    uint32 // number of passes over the memory
	Memory  uint32 // size of memory in KiB
	Threads uint8  // CPU threads to use
	KeySize uint32 // desired key size
}

func NewArgon2() *Argon2 {
	return &Argon2{
		NameStr: "argon2",
		DescStr: "argon2 key derivation function",

		Time:    1,
		Memory:  64 * 1024,
		Threads: 1,
		KeySize: 64,
	}
}

func (kg *Argon2) Name() string {
	return kg.NameStr
}

func (kg *Argon2) Description() string {
	return kg.DescStr
}

func (kg *Argon2) DeriveKey(psw string, salt []byte) ([]byte, error) {
	return argon2.IDKey([]byte(psw), salt, kg.Time, kg.Memory, kg.Threads, kg.KeySize), nil
}
