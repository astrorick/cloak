package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/astrorick/cloak/pkg/algos"
	"github.com/astrorick/cloak/pkg/keygen"
	"github.com/astrorick/cloak/pkg/pswgen"
	"github.com/astrorick/cloak/pkg/utils"
	"github.com/spf13/cobra"
)

// newEncryptCommand returns the "encrypt" command, which encrypts the input file with a key file or a password and writes the result to the output file.
func newEncryptCommand() *cobra.Command {
	var (
		//* Encrypt Command Flags */
		encryptKeyFilePath    string // path to the cryptographic key (for key-based encryption)
		encryptPassword       string // password to be used for encryption
		encryptMethodName     string // key derivation method (for password-based encryption)
		encryptAlgorithmName  string // name of algorithm used for encryption
		encryptForceOverwrite bool   // whether to automatically overwrite output file
		encryptDeleteOriginal bool   // whether to delete the source file after encryption
	)

	//* Encrypt Command */
	encryptCommand := &cobra.Command{
		Use:   "encrypt input output",
		Short: "Encrypt files",
		Long:  "Encrypt the file provided as input with the algorithm specified after the optional -a flag and write the result to the output file path. Either a cryptographic key file or a password can be used for encryption. If the optional -d flag is passed, the source file is then deleted.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			//* Input/Output File Checks

			// read input and output file paths from args
			inputFilePath := args[0]
			outputFilePath := args[1]

			// check that the input file actually exists
			inputFileExists, inputFileInfo, err := utils.FileExists(inputFilePath)
			if err != nil {
				return fmt.Errorf("input path error: %w", err)
			}
			if !inputFileExists {
				return fmt.Errorf("input file \"%s\" does not exist", inputFilePath)
			}

			// check that the input file is NOT the same as the output file, as it could be overwritten or deleted
			outputFileExists, outputFileInfo, err := utils.FileExists(outputFilePath)
			if err != nil {
				return fmt.Errorf("output path error: %w", err)
			}
			if os.SameFile(inputFileInfo, outputFileInfo) {
				return errors.New("input file and output file must be different")
			}

			// verify whether the output file already exists, eventually asking the user if he wants to overwrite it
			if outputFileExists && !encryptForceOverwrite && !utils.ConfirmOverwrite(outputFilePath) {
				return errors.New("operation cancelled by user")
			}

			//* Flag Checks

			// make sure the user did NOT specify both a key file and a password
			if encryptKeyFilePath != "" && encryptPassword != "" {
				return errors.New("flag error: flag -k and flag -p are mutually exclusive")
			}

			// check crypto algorithm
			cryptoAlgorithm, ok := algos.ImplementedAlgos[encryptAlgorithmName]
			if !ok {
				return fmt.Errorf("unsupported crypto algorithm \"%s\"", encryptAlgorithmName)
			}

			//* Input File Reading

			// open input file as read only with [os.Open]
			inputFile, err := os.Open(inputFilePath)
			if err != nil {
				return fmt.Errorf("error opening input file \"%s\": %w", inputFilePath, err)
			}
			defer inputFile.Close() // this can be deferred safely since the input file is read only

			// read content of input file (this happens before key derivation to mirror decryption, where the salt is stored in the input file)
			plainBytes, err := io.ReadAll(inputFile)
			if err != nil {
				return fmt.Errorf("error reading input file \"%s\": %w", inputFilePath, err)
			}

			//* Key-Based or Password-Based Encryption Branching

			// load cryptographic key OR derive one from the password provided by the user
			var salt, key []byte
			if encryptKeyFilePath != "" { //* user wants to use encryption key, load it and validate it
				// check if the key file exists
				keyFileExists, keyFileInfo, err := utils.FileExists(encryptKeyFilePath)
				if err != nil {
					return fmt.Errorf("key file path error: %w", err)
				}
				if !keyFileExists {
					return fmt.Errorf("key file \"%s\" does not exist", encryptKeyFilePath)
				}

				// make sure the output file is NOT the same as the key file, as this could overwrite the crypto key
				if os.SameFile(keyFileInfo, outputFileInfo) {
					return errors.New("key file and output file must be different")
				}

				// open key file and read its content
				keyFile, err := os.Open(encryptKeyFilePath)
				if err != nil {
					return fmt.Errorf("error opening key file \"%s\": %w", encryptKeyFilePath, err)
				}
				defer keyFile.Close()
				key, err = io.ReadAll(keyFile)
				if err != nil {
					return fmt.Errorf("error reading key file \"%s\": %w", encryptKeyFilePath, err)
				}

				// check that the key length matches the standard key size defined in the keygen package
				if len(key) != keygen.StandardKeySizeBytes {
					return fmt.Errorf("invalid key file size (expected %d bytes, got %d)", keygen.StandardKeySizeBytes, len(key))
				}
			} else { //* user wants to use password for encryption, derive crypto key from it
				// check key derivation method
				method, ok := keygen.ImplementedMethods[encryptMethodName]
				if !ok {
					return fmt.Errorf("unsupported key derivation method \"%s\"", encryptMethodName)
				}

				// generate random salt for key derivation (this happens before asking for a password to mirror decryption, where the salt is split from the input file first)
				salt = make([]byte, 16)
				if _, err := rand.Read(salt); err != nil {
					return fmt.Errorf("error generating random salt: %w", err)
				}

				// check if user provided a password via the -p flag and ask otherwise
				if encryptPassword != "" {
					// validate user-provided password passed by the -p flag
					if !pswgen.ValidatePassword(encryptPassword) {
						return errors.New("invalid password")
					}
				} else {
					// request the user inputs its password from terminal
					encryptPassword, err = utils.RequestUserPassword(true) // ask for double confirmation
					if err != nil {
						return fmt.Errorf("error reading password from terminal: %w", err)
					}
				}

				// derive encryption key from user password and salt using the standard key size defined in the keygen package
				key, err = method.DeriveKey(encryptPassword, salt)
				if err != nil {
					return fmt.Errorf("error generating cryptographic key: %w", err)
				}
			}

			//* Encryption and Output File Handling

			// encrypt content of input file
			nonce, cipherBytes, err := cryptoAlgorithm.Encrypt(plainBytes, key)
			if err != nil {
				return fmt.Errorf("error encrypting input file: %w", err)
			}

			// assemble output data as salt + nonce + ciphertext (salt is nil for key-based encryption, leaving nonce + ciphertext)
			outputBytes := slices.Concat(salt, nonce, cipherBytes)

			// open output file as read/write with [os.Create], only after encryption succeeded so that a failure leaves an existing output file untouched
			outputFile, err := os.Create(outputFilePath)
			if err != nil {
				return fmt.Errorf("error creating output file \"%s\": %w", outputFilePath, err)
			}
			defer outputFile.Close() // this only functions as a safety measure in case writing to output file fails (the file would never be closed)

			// write data to output file
			if _, err := outputFile.Write(outputBytes); err != nil {
				return fmt.Errorf("error writing encrypted data to output file: %w", err)
			}

			// explicitly close output file BEFORE eventually deleting original to avoid mishaps
			if err = outputFile.Close(); err != nil {
				return fmt.Errorf("error saving output file: %w", err)
			}

			// delete original file if requested
			if encryptDeleteOriginal {
				if err := os.Remove(inputFilePath); err != nil {
					return fmt.Errorf("error deleting input file \"%s\" after encryption: %w", inputFilePath, err)
				}
			}

			return nil
		},
	}
	encryptCommand.Flags().StringVarP(&encryptKeyFilePath, "key", "k", "", "path to key file used for encryption")
	encryptCommand.Flags().StringVarP(&encryptPassword, "password", "p", "", "password used for encryption")
	encryptCommand.Flags().StringVarP(&encryptMethodName, "method", "m", keygen.DefaultMethod.Name(), "key derivation method")
	encryptCommand.Flags().StringVarP(&encryptAlgorithmName, "algorithm", "a", algos.DefaultAlgo.Name(), "encryption algorithm")
	encryptCommand.Flags().BoolVarP(&encryptForceOverwrite, "force", "f", false, "overwrite output file without asking")
	encryptCommand.Flags().BoolVarP(&encryptDeleteOriginal, "delete", "d", false, "delete source file after encryption")

	return encryptCommand
}
