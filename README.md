# Cloak

![Go Version](https://img.shields.io/github/go-mod/go-version/astrorick/cloak)
[![Go Reference](https://pkg.go.dev/badge/github.com/astrorick/cloak.svg)](https://pkg.go.dev/github.com/astrorick/cloak)
[![Go Report Card](https://goreportcard.com/badge/github.com/astrorick/cloak)](https://goreportcard.com/report/github.com/astrorick/cloak)
![License](https://img.shields.io/github/license/astrorick/cloak)
[![Latest Release](https://img.shields.io/github/v/release/astrorick/cloak?label=release)](https://github.com/astrorick/cloak/releases)

_Cloak_ is a minimal CLI tool for encrypting and decrypting files.

## Features

Here's a list of currently available features:

- Simple password-based or key-based file encryption and decryption.
- Support for **AES-GCM** (128-bit, 192-bit, 256-bit) and **ChaCha20-Poly1305** crypto algorithms.
- Support for password-based key derivation using **Argon2id** or **PBKDF2**.
- Support for completely random cryptographic key generation in key-based encryption/decryption.
- Non-interactive operation by injecting password or key file with appropriate flags.
- Utility flag to automatically overwrite the destination file.
- Utility flag to optinally delete the source file after encryption/decryption.
- Utility commands to list implemented algorithms and key-derivation methods.

## Quick Start

Defaults: **crypto-algorithm** = `AES-GCM-256`, **key-derivation-method** = `Argon2id`.

**Encryption (interactive, will prompt for password)**:

```
cloak enc source.txt cipher.clk
```

**Decryption (interactive, will prompt for password)**:

```
cloak dec cipher.clk plain.txt
```

**Help**

```
cloak help
```

## Detailed Usage

```
cloak <command> [args] [flags]
```

> [!NOTE]
> Password-based and key-based operations are not compatible with each other. Files encrypted with one mode can only be decrypted successfully with the same mode.

**Main Commands:**

- `keygen`: generates a random 64-byte cryptographic key and writes it to the file provided as the `output` argument (will automatically fail if the destination file already exists).

  **Args**:
  - `output`: output file path for saving the newly generated cryptographic key.

  **Flags**:
  - `-h`, `--help`: show help for this command.

---

- `enc`: encrypts the input file and writes the resulting ciphertext to the output file. Either a user-provided password or a key file can be used for encryption.

  **Args**:
  - `input_file`: source file to be encrypted (will fail if this file does not exist).
  - `output_file`: destination for saving the ciphertext (will ask for permission to overwrite if the output file already exists and the optional `-f` flag was _not_ passed).

  **Flags**:
  - `-a`, `--algorithm`: encryption algorithm (must be one of `aesgcm128`, `aesgcm192`, `aesgcm256`, `chacha20poly1305`; defaults to `aesgcm256` if unspecified).
  - `-m`, `--method`: key-derivation method for password-based encryption (must be one of `argon2`, `pbkdf2`; defaults to `argon2` if unspecified).
  - `-p`, `--password`: provide password non-interactively (mutually exclusive with `-k`, must be >= 8 chars, printable ASCII).
  - `-k`, `--key`: path to a 64-byte key file for key-based encryption (mutually exclusive with `-p`).
  - `-f`, `--force`: overwrite the output file without prompting.
  - `-d`, `--delete`: delete source file after successful operation.
  - `-h`, `--help`: show help for this command.

---

- `dec`: decrypts the input file and writes the resulting plaintext to the output file. Either a password (interactive or `-p`) or a key file (`-k`) can be used for decryption.

  **Args**:
  - `input_file`: source file to be decrypted (will fail if this file does not exist).
  - `output_file`: destination for saving the plaintext (will ask for permission to overwrite if the output file already exists and the optional `-f` flag was _not_ passed).

  **Flags**:
  - `-a`, `--algorithm`: decryption algorithm (must be one of `aesgcm128`, `aesgcm192`, `aesgcm256`, `chacha20poly1305`; defaults to `aesgcm256` if unspecified).
  - `-m`, `--method`: key-derivation method for password-based decryption (must be one of `argon2`, `pbkdf2`; defaults to `argon2` if unspecified).
  - `-p`, `--password`: provide password non-interactively (mutually exclusive with `-k`, must be >= 8 chars, printable ASCII).
  - `-k`, `--key`: path to a 64-byte key file for key-based decryption (mutually exclusive with `-p`).
  - `-f`, `--force`: overwrite the output file without prompting.
  - `-d`, `--delete`: delete source file after successful operation.
  - `-h`, `--help`: show help for this command.

**Utility Commands:**

- `algos`: prints a list of implemented cryptographic algorithms and highlights the default value.

---

- `methods`: prints a list of implemented key-derivation methods and highlights the default value.

---

- `version`: prints the program version.

## Usage Examples

Interactive **encryption** using default crypto algorithm and default key derivation method, prompting for password:

```
cloak enc source.txt cipher.clk
```

---

Interactive **decryption** using default crypto algorithm and default key derivation method, prompting for password:

```
cloak dec cipher.clk plain.txt
```

---

Non-interactive **encryption** with injected password using default crypto algorithm and key derivation method:

```
cloak enc source.txt cipher.clk -p my_strong_password
```

---

Non-interactive **decryption** with injected password, custom crypto algorithm and key derivarion method, force overwrite and delete source if successful:

```
cloak dec cipher.clk plain.txt -p my_strong_password -a chacha20poly1305 -m pbkdf2 -f -d
```

---

Key-based **encryption** using a newly-generated 64-byte static cryptographic key and default crypto algorithm:

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
