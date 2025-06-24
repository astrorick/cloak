# Cloak

![Go Version](https://img.shields.io/github/go-mod/go-version/astrorick/cloak)
[![Go Report Card](https://goreportcard.com/badge/github.com/astrorick/cloak)](https://goreportcard.com/report/github.com/astrorick/cloak)
[![Go Reference](https://pkg.go.dev/badge/github.com/astrorick/cloak.svg)](https://pkg.go.dev/github.com/astrorick/cloak)
[![Latest Release](https://img.shields.io/github/v/release/astrorick/cloak?label=release)](https://github.com/astrorick/cloak/releases)
![License](https://img.shields.io/github/license/astrorick/cloak)

_Cloak_ is a minimal CLI tool for encrypting and decrypting files.

## Features

Here's a list of currently available features:

- Simple file encryption and decryption
- Supports multiple cryptography algorithms
- Lightweight and easy to use

## Work In Progress

Here's a list of planned features I'm currently working on:

- [ ] Implement additional cryptography algorithms
- [x] Improve salt generation logic and storage
- [ ] Implement successful decryption check

## Usage

**Encrypting a file**

```
cloak enc source_file encrypted_file
```

**Decrypting a file**

```
cloak dec encrypted_file output_file
```

**Program help**

```
cloak help
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
