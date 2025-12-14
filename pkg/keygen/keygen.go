package keygen

// Keygen is the interface that each implemented key derivation method must satisfy.
type Keygen interface {
	Name() string
	Description() string

	DeriveKey(psw string, salt []byte) ([]byte, error)
}

// Implemented maps implemented methods to their internal name.
var Implemented = map[string]Keygen{
	"argon2": NewArgon2Keygen(),
	"pbkdf2": NewPBKDF2Keygen(),
}

// Default represents the default key generation function used when no flag is passed.
var Default = Implemented["argon2"]
