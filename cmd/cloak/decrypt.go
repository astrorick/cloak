package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/astrorick/cloak/pkg/algos"
	"github.com/astrorick/cloak/pkg/keygen"
	"github.com/astrorick/cloak/pkg/pswgen"
	"github.com/astrorick/cloak/pkg/utils"
	"github.com/spf13/cobra"
)

// newDecryptCommand returns the "decrypt" command, which decrypts the input file with a key file or a password and writes the result to the output file.
func newDecryptCommand() *cobra.Command {
	var (
		//* Decrypt Command Flags */
		decryptKeyFilePath    string // path to the cryptographic key (for key-based decryption)
		decryptPassword       string // password to be used for decryption
		decryptMethodName     string // key derivation method (for password-based decryption)
		decryptAlgorithmName  string // name of algorithm used for decryption
		decryptForceOverwrite bool   // whether to automatically overwrite output file
		decryptDeleteOriginal bool   // whether to delete the source file after decryption
	)

	//* Decrypt Command */
	decryptCommand := &cobra.Command{
		Use:   "decrypt input output",
		Short: "Decrypt files",
		Long:  "Decrypt the file provided as input with the algorithm specified after the optional -a flag and write the result to the output file path. Either a cryptographic key file or a password can be used for decryption. If the optional -d flag is passed, the source file is then deleted.",
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
			if outputFileExists && !decryptForceOverwrite && !utils.ConfirmOverwrite(outputFilePath) {
				return errors.New("operation cancelled by user")
			}

			//* Flag Checks

			// make sure the user did NOT specify both a key file and a password
			if decryptKeyFilePath != "" && decryptPassword != "" {
				return errors.New("flag error: flag -k and flag -p are mutually exclusive")
			}

			// check crypto algorithm
			cryptoAlgorithm, ok := algos.ImplementedAlgos[decryptAlgorithmName]
			if !ok {
				return fmt.Errorf("unsupported crypto algorithm \"%s\"", decryptAlgorithmName)
			}

			//* Input File Reading

			// open input file as read only with [os.Open]
			inputFile, err := os.Open(inputFilePath)
			if err != nil {
				return fmt.Errorf("error opening input file \"%s\": %w", inputFilePath, err)
			}
			defer inputFile.Close() // this can be deferred safely since the input file is read only

			// read content of input file (this must happen before key derivation, as the salt is stored in the input file)
			cipherBytes, err := io.ReadAll(inputFile)
			if err != nil {
				return fmt.Errorf("error reading input file \"%s\": %w", inputFilePath, err)
			}

			//* Key-Based or Password-Based Decryption Branching

			// load cryptographic key OR derive one from the password provided by the user
			var salt, key []byte
			if decryptKeyFilePath != "" { //* user wants to use decryption key, load it and validate it
				// check if the key file exists
				keyFileExists, keyFileInfo, err := utils.FileExists(decryptKeyFilePath)
				if err != nil {
					return fmt.Errorf("key file path error: %w", err)
				}
				if !keyFileExists {
					return fmt.Errorf("key file \"%s\" does not exist", decryptKeyFilePath)
				}

				// make sure the output file is NOT the same as the key file, as this could overwrite the crypto key
				if os.SameFile(keyFileInfo, outputFileInfo) {
					return errors.New("key file and output file must be different")
				}

				// open key file and read its content
				keyFile, err := os.Open(decryptKeyFilePath)
				if err != nil {
					return fmt.Errorf("error opening key file \"%s\": %w", decryptKeyFilePath, err)
				}
				defer keyFile.Close()
				key, err = io.ReadAll(keyFile)
				if err != nil {
					return fmt.Errorf("error reading key file \"%s\": %w", decryptKeyFilePath, err)
				}

				// check that the key length matches the standard key size defined in the keygen package
				if len(key) != keygen.StandardKeySizeBytes {
					return fmt.Errorf("invalid key file size (expected %d bytes, got %d)", keygen.StandardKeySizeBytes, len(key))
				}
			} else { //* user wants to use password for decryption, derive crypto key from it
				// check key derivation method
				method, ok := keygen.ImplementedMethods[decryptMethodName]
				if !ok {
					return fmt.Errorf("unsupported key derivation method \"%s\"", decryptMethodName)
				}

				// split salt from nonce + ciphertext, before asking for a password that could not be used anyway
				if len(cipherBytes) < 16 {
					return errors.New("invalid encrypted file format (too short for password-based decryption)")
				}
				salt, cipherBytes = cipherBytes[:16], cipherBytes[16:]

				// check if user provided a password via the -p flag and ask otherwise
				if decryptPassword != "" {
					// validate user-provided password passed by the -p flag
					if !pswgen.ValidatePassword(decryptPassword) {
						return errors.New("invalid password")
					}
				} else {
					// request the user inputs its password from terminal
					decryptPassword, err = utils.RequestUserPassword(false) // no confirmation needed
					if err != nil {
						return fmt.Errorf("error reading password from terminal: %w", err)
					}
				}

				// derive decryption key from user password and salt using the standard key size defined in the keygen package
				key, err = method.DeriveKey(decryptPassword, salt)
				if err != nil {
					return fmt.Errorf("error generating cryptographic key: %w", err)
				}
			}

			//* Decryption and Output File Handling

			// split nonce from ciphertext (the salt has already been stripped for password-based decryption)
			nonceSize := cryptoAlgorithm.NonceSize()
			nonce := cipherBytes[:nonceSize]
			cipherBytes = cipherBytes[nonceSize:]

			// decrypt content of input file
			plainBytes, err := cryptoAlgorithm.Decrypt(nonce, cipherBytes, key)
			if err != nil {
				return fmt.Errorf("error decrypting input file: %w", err)
			}

			// open output file as read/write with [os.Create], only after decryption succeeded so that a wrong key or password leaves an existing output file untouched
			outputFile, err := os.Create(outputFilePath)
			if err != nil {
				return fmt.Errorf("error creating output file \"%s\": %w", outputFilePath, err)
			}
			defer outputFile.Close() // this only functions as a safety measure in case writing to output file fails (the file would never be closed)

			// write data to output file
			if _, err := outputFile.Write(plainBytes); err != nil {
				return fmt.Errorf("error writing decrypted data to output file: %w", err)
			}

			// explicitly close output file BEFORE eventually deleting original to avoid mishaps
			if err = outputFile.Close(); err != nil {
				return fmt.Errorf("error saving output file: %w", err)
			}

			// delete original file if requested
			if decryptDeleteOriginal {
				if err := os.Remove(inputFilePath); err != nil {
					return fmt.Errorf("error deleting input file \"%s\" after decryption: %w", inputFilePath, err)
				}
			}

			return nil
		},
	}
	decryptCommand.Flags().StringVarP(&decryptKeyFilePath, "key", "k", "", "path to key file used for decryption")
	decryptCommand.Flags().StringVarP(&decryptPassword, "password", "p", "", "password used for decryption")
	decryptCommand.Flags().StringVarP(&decryptMethodName, "method", "m", keygen.DefaultMethod.Name(), "key derivation method")
	decryptCommand.Flags().StringVarP(&decryptAlgorithmName, "algorithm", "a", algos.DefaultAlgo.Name(), "decryption algorithm")
	decryptCommand.Flags().BoolVarP(&decryptForceOverwrite, "force", "f", false, "overwrite output file without asking")
	decryptCommand.Flags().BoolVarP(&decryptDeleteOriginal, "delete", "d", false, "delete source file after decryption")

	return decryptCommand
}
