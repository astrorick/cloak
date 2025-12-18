# Cloak

![Go Version](https://img.shields.io/github/go-mod/go-version/astrorick/cloak)
[![Go Reference](https://pkg.go.dev/badge/github.com/astrorick/cloak.svg)](https://pkg.go.dev/github.com/astrorick/cloak)
[![Go Report Card](https://goreportcard.com/badge/github.com/astrorick/cloak)](https://goreportcard.com/report/github.com/astrorick/cloak)
![License](https://img.shields.io/github/license/astrorick/cloak)
[![Latest Release](https://img.shields.io/github/v/release/astrorick/cloak?label=release)](https://github.com/astrorick/cloak/releases)

_Cloak_ is a minimal CLI tool for encrypting and decrypting files.

## Features

Here's a list of currently available features:

- Simple file encryption and decryption (password-based or key-based).
- Supports AES-GCM (aesgcm128, aesgcm192, aesgcm256) and ChaCha20-Poly1305 crypto algorithms.
- Password-based key derivation with **Argon2** and **PBKDF2** (configurable via `-m`/`--method`).
- Generate and use static 64-byte cryptographic keys with `keygen` and `-k`/`--key`.
- Non-interactive operation: inject password with `-p`/`--password` or use a key file with `-k`/`--key`.
- Overwrite control (`-f`/`--force`) and optional source deletion after operation (`-d`/`--delete`).
- Commands to list implemented algorithms (`algos`) and key-derivation methods (`methods`).

## Quick Start

Defaults: **algorithm** = `aesgcm256` (displayed as "aes256" in docs) and **key-derivation** = `argon2`.

**Encryption (interactive)**:

```
cloak enc source.txt cipher.clk
```

**Decryption (interactive)**:

```
cloak dec cipher.clk plain.txt
```

**Help**

```
cloak help
```

## Detailed Usage

```
cloak [command] [flags]
```

**Available Commands:**

- `keygen output`: Generate a random 64-byte cryptographic key and write it to `output` (will automatically fail if `output` already exists).

- `enc input_file output_file`: Encrypt the input file and write the resulting ciphertext to the output file. Either a password (interactive or `-p`) or a key file (`-k`) can be used.

  Flags:
  - `-h`, `--help`: show help for any command.
  - `-a`, `--algorithm`: encryption algorithm (one of `aesgcm128`, `aesgcm192`, `aesgcm256`, `chacha20poly1305`; default: `aesgcm256`).
  - `-k`, `--key`: path to a 64-byte key file for key-based encryption (mutually exclusive with `-p`).
  - `-p`, `--password`: provide password non-interactively (mutually exclusive with `-k`, must be >= 8 chars, printable ASCII).
  - `-m`, `--method`: key-derivation method for password-based encryption (one of `argon2`, `pbkdf2`; default: `argon2`).
  - `-f`, `--force`: overwrite the output file without prompting.
  - `-d`, `--delete`: delete source file after successful operation.

- `dec input_file output_file`: Decrypt the input file and write the resulting plaintext to the output file. Either a password (interactive or `-p`) or a key file (`-k`) can be used.

  Flags:
  - `-h`, `--help`: show help for any command.
  - `-a`, `--algorithm`: decryption algorithm (one of `aesgcm128`, `aesgcm192`, `aesgcm256`, `chacha20poly1305`; default: `aesgcm256`).
  - `-k`, `--key`: path to a 64-byte key file for key-based decryption (mutually exclusive with `-p`).
  - `-p`, `--password`: provide password non-interactively (mutually exclusive with `-k`, must be >= 8 chars, printable ASCII).
  - `-m`, `--method`: key-derivation method for password-based decryption (one of `argon2`, `pbkdf2`; default: `argon2`).
  - `-f`, `--force`: overwrite the output file without prompting.
  - `-d`, `--delete`: delete source file after successful operation.

- `algos`: List implemented cryptographic algorithms.

- `methods`: List implemented key-derivation methods.

- `version`: Print the program version.

> [!NOTE]
> Password-based encryption and key-based encryption are not compatible with each other. Files ancrypted with one of these modes must be decrypted with the same mode.

## Usage Examples

Interactive encryption using default algorithm and key derivation method, prompts for password:

```
cloak enc source.txt cipher.clk
```

---

Non-interactive encryption with injected password and custom algorithm/method, force overwrite and delete source:

```
cloak enc source.txt cipher.clk -p my_strong_password -a chacha20poly1305 -m pbkdf2 -f -d
```

---

Non-interactive decryption with injected password using default algorithm and key derivation method:

```
cloak dec cipher.clk plain.txt -p my_strong_password
```

---

Key-based encryption using a static cryptographic key file:

```
cloak keygen mykey.bin
cloak enc source.txt cipher.clk -k mykey.bin
```

## Contributing

Contributions are welcome and encouraged!

Here are a few key steps you can follow to make the process smoother:

- Fork this repository and create a new branch for your feature or fix.
- Make your changes by following the project's coding/writing style and ensure to produce consistent results before submitting.
- Open a new pull request and include a clear description of your changes.

For detailed guidelines, refer to the [CONTRIBUTING.md](CONTRIBUTING.md) file.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
