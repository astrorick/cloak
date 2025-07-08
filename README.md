# Cloak

![Go Version](https://img.shields.io/github/go-mod/go-version/astrorick/cloak)
[![Go Reference](https://pkg.go.dev/badge/github.com/astrorick/cloak.svg)](https://pkg.go.dev/github.com/astrorick/cloak)
[![Go Report Card](https://goreportcard.com/badge/github.com/astrorick/cloak)](https://goreportcard.com/report/github.com/astrorick/cloak)
![License](https://img.shields.io/github/license/astrorick/cloak)
[![Latest Release](https://img.shields.io/github/v/release/astrorick/cloak?label=release)](https://github.com/astrorick/cloak/releases)

_Cloak_ is a minimal CLI tool for encrypting and decrypting files.

## Features

Here's a list of currently available features:

- Simple file encryption and decryption
- Supports multiple state-of-the-art cryptography algorithms
- Lightweight and easy to use

## Work In Progress

Here's a list of planned features I'm currently working on:

- [ ] Implement additional cryptography algorithms
- [ ] Implement successful decryption check

## Quick Start

The `AES256` algorithm will be selected by default when not explicitly specified by the `-x` flag.

**Encryption**

```
cloak enc source_file encrypted_file
```

**Decryption**

```
cloak dec encrypted_file output_file
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
- `enc`: encrypt the input file into the output file using the optionally specified algorithm (defaults to `aes256`)

  ```
  cloak enc input_file output_file [flags]
  ```

  **Available Flags:**
  - `-h` or `--help`: display the encryption help message
  - `-x` or `--algorithm`: specify the encryption algorithm (`aes128`, `aes192`, `aes256` or `chacha20poly1305`)
  - `-r` or `--replace`: remove input file after encryption

- `dec`: decrypt the input file into the output file using the optionally specified algorithm (defaults to `aes256`)

  ```
  cloak dec input_file output_file [flags]
  ```

  **Available Flags:**
  - `-h` or `--help`: display the decryption help message
  - `-x` or `--algorithm`: specify the decryption algorithm (`aes128`, `aes192`, `aes256` or `chacha20poly1305`)
  - `-r` or `--replace`: remove input file after encryption

- `version`: print current program version (equivalent to the `-v` and `--version` flags)

- `help`: display the general help message (equivalent to the `-h` and `--help` flags)

**Available Flags:**
- `-v` or `--version`: print current program version (equivalent to the `version` command)
- `-h` or `--help`: display the general help message (equivalent to the `help` command)

## Usage Examples

1. Encrypt `my_plaintext_file.txt` using the `chacha20poly1305` algorithm. Write the result to `my_encrypted_file.clk` and _remove_ the source file if successful:

   ```
   cloak enc my_plaintext_file.txt my_encrypted_file.clk -x chacha20poly1305 -r
   ```

2. Decrypt `secret.clk` using the `aes192` algorithm. Write the result to `selfie.jpg` but _keep_ the source file:

   ```
   cloak dec secret.clk selfie.jpg -x aes192
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
