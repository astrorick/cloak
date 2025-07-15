package algos

type KeyConfig struct {
	KeyType    string
	KeyTime    uint32
	KeyMemory  uint32
	KeyThreads uint8
	KeySize    uint32
}

type SymmetricAlgorithm struct {
	Name      string
	SaltSize  uint64
	NonceSize uint64
	KeyConfig *KeyConfig
}

var MyAES128 = &SymmetricAlgorithm{
	Name: "aes128",

	SaltSize:  16,
	NonceSize: 12,

	KeyConfig: &KeyConfig{
		KeyTime:    8,
		KeyMemory:  128 * 1024,
		KeyThreads: 4,
		KeySize:    16,
	},
}
var MyAES192 = &SymmetricAlgorithm{
	Name: "aes192",

	SaltSize:  16,
	NonceSize: 12,

	KeyConfig: &KeyConfig{
		KeyTime:    8,
		KeyMemory:  128 * 1024,
		KeyThreads: 4,
		KeySize:    24,
	},
}
var MyAES256 = &SymmetricAlgorithm{
	Name: "aes256",

	SaltSize:  16,
	NonceSize: 12,

	KeyConfig: &KeyConfig{
		KeyTime:    8,
		KeyMemory:  128 * 1024,
		KeyThreads: 4,
		KeySize:    32,
	},
}
