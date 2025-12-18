package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/astrorick/cloak/pkg/algos"
	"github.com/astrorick/cloak/pkg/keygen"
	"github.com/astrorick/cloak/pkg/utils"
	"github.com/astrorick/semantika"
	"github.com/spf13/cobra"
)

func main() {
	//* Program Version */
	appVersion := &semantika.Version{
		Major: 0,
		Minor: 5,
		Patch: 0,
	}

	var (
		//* Root Command Flags */
		rootDisplayVersion bool // whether to display program version and exit

		//* Encrypt Command Flags */
		encryptKeyFilePath    string // path to the cryptographic key (for key-based encryption)
		encryptPassword       string // password to be used for encryption
		encryptMethodName     string // key derivation method (for password-based encryption)
		encryptAlgorithmName  string // name of algorithm used for encryption
		encryptForceOverwrite bool   // whether to automatically overwrite output file
		encryptDeleteOriginal bool   // whether to delete the source file after encryption

		//* Decrypt Command Flags */
		decryptKeyFilePath    string // path to the cryptographic key (for key-based decryption)
		decryptPassword       string // password to be used for decryption
		decryptMethodName     string // key derivation method (for password-based decryption)
		decryptAlgorithmName  string // name of algorithm used for decryption
		decryptForceOverwrite bool   // whether to automatically overwrite output file
		decryptDeleteOriginal bool   // whether to delete the source file after decryption
	)

	//* Root Command */
	rootCommand := &cobra.Command{
		Use:   "cloak",
		Short: "Cloak allows you to encrypt and decrypt files using a cryptographic key or a password.",
		Run: func(cmd *cobra.Command, args []string) {
			// if version flag is passed, display program version and exit
			if rootDisplayVersion {
				utils.PrintVersion(appVersion)
				os.Exit(0)
			}

			// if no args are provided, display help and exit
			if len(args) == 0 {
				_ = cmd.Help()
				os.Exit(1)
			}
		},
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true, // this disables the "completion" command which is shown dy default
		},
	}
	rootCommand.Flags().BoolVarP(&rootDisplayVersion, "version", "v", false, "program version")

	//* Keygen Command */
	keygenCommand := &cobra.Command{
		Use:   "keygen output",
		Short: "Generate crypto keys",
		Long:  "Generate a static cryptographic key of fixed size that can be used to encrypt and decrypt files, and save it to the specified location.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			// read args
			outputFilePath := args[0]

			// check that output file does not already exist, but NEVER OVERWRITE
			outputFileExists, err := utils.FileExists(outputFilePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "output path error: %v\n", err)
				os.Exit(1)
			}
			if outputFileExists {
				fmt.Fprintf(os.Stderr, "output file \"%s\" already exists, aborting\n", outputFilePath)
				os.Exit(1)
			}

			// generate random cryptographic key
			key, err := keygen.GenerateRandomKey()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error generating random key: %v\n", err)
				os.Exit(1)
			}

			// open output file
			outputFile, err := os.Create(outputFilePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error creating output file: %v\n", err)
				os.Exit(1)
			}
			defer outputFile.Close()

			// write key to output file
			if _, err := outputFile.Write(key); err != nil {
				fmt.Fprintf(os.Stderr, "error writing to output file: %v\n", err)
				os.Exit(1)
			}
		},
	}

	//* Encrypt Command */
	encryptCommand := &cobra.Command{
		Use:   "enc input output",
		Short: "Encrypt files",
		Long:  "Encrypt the file provided as input with the algorithm specified after the optional -a flag and write the result to the output file path. Either a cryptographic key file or a password can be used for encryption. If the optional -d flag is passed, the source file is then deleted.",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			// read input and output file paths from args
			inputFilePath := args[0]
			outputFilePath := args[1]

			// check chosen crypto algorithm
			algo, ok := algos.ImplementedAlgos[encryptAlgorithmName]
			if !ok {
				fmt.Fprintf(os.Stderr, "unsupported crypto algorithm \"%s\"\n", encryptAlgorithmName)
				os.Exit(1)
			}

			// check that the input file exists and open it
			inputFileExists, err := utils.FileExists(inputFilePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "input path error: %v\n", err)
				os.Exit(1)
			}
			if !inputFileExists {
				fmt.Fprintf(os.Stderr, "input file \"%s\" does not exist\n", inputFilePath)
				os.Exit(1)
			}
			inputFile, err := os.Open(inputFilePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error opening input file \"%s\": %v\n", inputFilePath, err)
				os.Exit(1)
			}
			defer inputFile.Close()

			// check that the output file does not already exist, eventually asking the user if he wants to overwrite it, and create it
			outputFileExists, err := utils.FileExists(outputFilePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "output path error: %v\n", err)
				os.Exit(1)
			}
			if outputFileExists && !encryptForceOverwrite && !utils.ConfirmOverwrite(outputFilePath) {
				fmt.Fprintf(os.Stderr, "operation cancelled by user\n")
				os.Exit(1)
			}
			outputFile, err := os.Create(outputFilePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error creating output file \"%s\": %v\n", outputFilePath, err)
				os.Exit(1)
			}
			defer outputFile.Close()

			// read entire input file
			plainBytes, err := io.ReadAll(inputFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error reading input file \"%s\": %v\n", inputFilePath, err)
				os.Exit(1)
			}

			// load cryptographic key OR derive one from the user-provided password
			var salt, key []byte
			if encryptKeyFilePath != "" { //* load (and validate) key file
				// make sure the user did NOT specify both a key file and a password flag
				if encryptPassword != "" {
					fmt.Fprintf(os.Stderr, "flag error: flag -k can't be used with flag -p")
					os.Exit(1)
				}

				// check if the key file exists and open it
				keyFileExists, err := utils.FileExists(encryptKeyFilePath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "key file path error: %v\n", err)
					os.Exit(1)
				}
				if !keyFileExists {
					fmt.Fprintf(os.Stderr, "key file \"%s\" does not exist\n", encryptKeyFilePath)
					os.Exit(1)
				}
				keyFile, err := os.Open(encryptKeyFilePath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error opening key file \"%s\": %v\n", encryptKeyFilePath, err)
					os.Exit(1)
				}
				defer keyFile.Close()

				// read key file
				key, err = io.ReadAll(keyFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error reading key file \"%s\": %v\n", encryptKeyFilePath, err)
					os.Exit(1)
				}

				// check that the key length is consistent
				if len(key) != 64 {
					fmt.Fprintf(os.Stderr, "invalid key file size (expected 64 bytes, got %d)\n", len(key))
					os.Exit(1)
				}
			} else { //* derive key from password
				// check key derivation method
				method, ok := keygen.ImplementedMethods[encryptMethodName]
				if !ok {
					fmt.Fprintf(os.Stderr, "unsupported key derivation method \"%s\"\n", encryptMethodName)
					os.Exit(1)
				}

				// check if user provided a -p flag
				if encryptPassword != "" {
					// validate user-provided password (passed by -p flag)
					if !utils.ValidatePassword(encryptPassword) {
						fmt.Fprintf(os.Stderr, "invalid password\n")
						os.Exit(1)
					}
				} else {
					// request the user inputs its password from terminal
					encryptPassword = utils.RequestUserPassword()
				}

				// generate random salt for key derivation
				salt = make([]byte, 16)
				if _, err := rand.Read(salt); err != nil {
					fmt.Fprintf(os.Stderr, "error generating random salt: %v\n", err)
					os.Exit(1)
				}

				// derive encryption key from user password and salt
				key, err = method.DeriveKey(encryptPassword, salt)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error generating cryptographic key: %v\n", err)
					os.Exit(1)
				}
			}

			// encrypt input file
			cipherBytes, err := algo.Encrypt(plainBytes, key)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error encrypting input file: %v\n", err)
				os.Exit(1)
			}

			// write data to output file
			if encryptKeyFilePath != "" { //* key-based encryption: write nonce + ciphertext
				if _, err := outputFile.Write(cipherBytes); err != nil {
					fmt.Fprintf(os.Stderr, "error writing encrypted data to output file: %v\n", err)
					os.Exit(1)
				}
			} else { //* password-based encryption: write salt + nonce + ciphertext
				if _, err := outputFile.Write(salt); err != nil {
					fmt.Fprintf(os.Stderr, "error writing salt to output file: %v\n", err)
					os.Exit(1)
				}
				if _, err := outputFile.Write(cipherBytes); err != nil {
					fmt.Fprintf(os.Stderr, "error writing encrypted data to output file: %v\n", err)
					os.Exit(1)
				}
			}

			// delete original file if requested
			if encryptDeleteOriginal {
				if err := os.Remove(inputFilePath); err != nil {
					fmt.Fprintf(os.Stderr, "error deleting input file \"%s\" after encryption: %v\n", inputFilePath, err)
					os.Exit(1)
				}
			}
		},
	}
	encryptCommand.Flags().StringVarP(&encryptKeyFilePath, "key", "k", "", "path to key file used for encryption")
	encryptCommand.Flags().StringVarP(&encryptPassword, "password", "p", "", "password used for encryption")
	encryptCommand.Flags().StringVarP(&encryptMethodName, "method", "m", keygen.DefaultMethod.Name(), "key derivation method")
	encryptCommand.Flags().StringVarP(&encryptAlgorithmName, "algorithm", "a", algos.DefaultAlgo.Name(), "encryption algorithm")
	encryptCommand.Flags().BoolVarP(&encryptForceOverwrite, "force", "f", false, "overwrite output file without asking")
	encryptCommand.Flags().BoolVarP(&encryptDeleteOriginal, "delete", "d", false, "delete source file after encryption")

	//* Decrypt Command */
	decryptCommand := &cobra.Command{
		Use:   "dec input output",
		Short: "Decrypt files",
		Long:  "Decrypt the file provided as input with the algorithm specified after the optional -a flag and write the result to the output file path. Either a cryptographic key file or a password can be used for decryption. If the optional -d flag is passed, the source file is then deleted.",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			// read input and output file paths from args
			inputFilePath := args[0]
			outputFilePath := args[1]

			// check chosen crypto algorithm
			algo, ok := algos.ImplementedAlgos[decryptAlgorithmName]
			if !ok {
				fmt.Fprintf(os.Stderr, "unsupported crypto algorithm \"%s\"\n", decryptAlgorithmName)
				os.Exit(1)
			}

			// check that the input file exists and open it
			inputFileExists, err := utils.FileExists(inputFilePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "input path error: %v\n", err)
				os.Exit(1)
			}
			if !inputFileExists {
				fmt.Fprintf(os.Stderr, "input file \"%s\" does not exist\n", inputFilePath)
				os.Exit(1)
			}
			inputFile, err := os.Open(inputFilePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error opening input file \"%s\": %v\n", inputFilePath, err)
				os.Exit(1)
			}
			defer inputFile.Close()

			// check that the output file does not already exist, eventually asking the user if he wants to overwrite it, and create it
			outputFileExists, err := utils.FileExists(outputFilePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "output path error: %v\n", err)
				os.Exit(1)
			}
			if outputFileExists && !decryptForceOverwrite && !utils.ConfirmOverwrite(outputFilePath) {
				fmt.Fprintf(os.Stderr, "operation cancelled by user\n")
				os.Exit(1)
			}
			outputFile, err := os.Create(outputFilePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error creating output file \"%s\": %v\n", outputFilePath, err)
				os.Exit(1)
			}
			defer outputFile.Close()

			// read entire input file
			cipherBytes, err := io.ReadAll(inputFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error reading input file \"%s\": %v\n", inputFilePath, err)
				os.Exit(1)
			}

			// load cryptographic key OR derive one from the user-provided password
			var salt, key []byte
			if decryptKeyFilePath != "" { //* load (and validate) key file
				// make sure the user did NOT specify both a key file and a password flag
				if decryptPassword != "" {
					fmt.Fprintf(os.Stderr, "flag error: flag -k can't be used with flag -p")
					os.Exit(1)
				}

				// check if the key file exists and open it
				keyFileExists, err := utils.FileExists(decryptKeyFilePath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "key file path error: %v\n", err)
					os.Exit(1)
				}
				if !keyFileExists {
					fmt.Fprintf(os.Stderr, "key file \"%s\" does not exist\n", decryptKeyFilePath)
					os.Exit(1)
				}
				keyFile, err := os.Open(decryptKeyFilePath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error opening key file \"%s\": %v\n", decryptKeyFilePath, err)
					os.Exit(1)
				}
				defer keyFile.Close()

				// read key file
				key, err = io.ReadAll(keyFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error reading key file \"%s\": %v\n", decryptKeyFilePath, err)
					os.Exit(1)
				}

				// check that the key length is consistent
				if len(key) != 64 {
					fmt.Fprintf(os.Stderr, "invalid key file size (expected 64 bytes, got %d)\n", len(key))
					os.Exit(1)
				}
			} else { //* derive key from password
				// check key derivation method
				method, ok := keygen.ImplementedMethods[decryptMethodName]
				if !ok {
					fmt.Fprintf(os.Stderr, "unsupported key derivation method \"%s\"\n", decryptMethodName)
					os.Exit(1)
				}

				// check if user provided a -p flag
				if decryptPassword != "" {
					// validate user-provided password (passed by -p flag)
					if !utils.ValidatePassword(decryptPassword) {
						fmt.Fprintf(os.Stderr, "invalid password\n")
						os.Exit(1)
					}
				} else {
					// request the user inputs its password from terminal
					decryptPassword = utils.RequestUserPassword()
				}

				// read salt for key derivation from file
				if len(cipherBytes) < 16 {
					fmt.Fprintf(os.Stderr, "invalid encrypted file format (too short for password-based decryption)\n")
					os.Exit(1)
				}
				salt = cipherBytes[:16]

				// derive decryption key from user password and salt
				key, err = method.DeriveKey(decryptPassword, salt)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error generating cryptographic key: %v\n", err)
					os.Exit(1)
				}
			}

			// decrypt input file
			var plainBytes []byte
			if decryptKeyFilePath != "" {
				// key-based decryption: decrypt nonce + ciphertext
				plainBytes, err = algo.Decrypt(cipherBytes, key)
			} else {
				// password-based decryption: decrypt nonce + ciphertext (after salt)
				plainBytes, err = algo.Decrypt(cipherBytes[16:], key)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "error decrypting input file: %v\n", err)
				os.Exit(1)
			}

			// write data to output file
			if _, err := outputFile.Write(plainBytes); err != nil {
				fmt.Fprintf(os.Stderr, "error writing decrypted data to output file: %v\n", err)
				os.Exit(1)
			}

			// delete original file if requested
			if decryptDeleteOriginal {
				if err := os.Remove(inputFilePath); err != nil {
					fmt.Fprintf(os.Stderr, "error deleting input file \"%s\" after decryption: %v\n", inputFilePath, err)
					os.Exit(1)
				}
			}
		},
	}
	decryptCommand.Flags().StringVarP(&decryptKeyFilePath, "key", "k", "", "path to key file used for decryption")
	decryptCommand.Flags().StringVarP(&decryptPassword, "password", "p", "", "password used for decryption")
	decryptCommand.Flags().StringVarP(&decryptMethodName, "method", "m", keygen.DefaultMethod.Name(), "key derivation method")
	decryptCommand.Flags().StringVarP(&decryptAlgorithmName, "algorithm", "a", algos.DefaultAlgo.Name(), "decryption algorithm")
	decryptCommand.Flags().BoolVarP(&decryptForceOverwrite, "force", "f", false, "overwrite output file without asking")
	decryptCommand.Flags().BoolVarP(&decryptDeleteOriginal, "delete", "d", false, "delete source file after decryption")

	//* Display Algos Command */
	algosCommand := &cobra.Command{
		Use:   "algos",
		Short: "List crypto algorithms",
		Long:  "Display the list of available cryptographic algorithms for encryption and decryption.",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Implemented algorithms:")

			for _, algoName := range algos.GetImplementedAlgoNames() {
				algo := algos.ImplementedAlgos[algoName]
				defaultMarker := ""
				if algoName == algos.DefaultAlgo.Name() {
					defaultMarker = " (default)"
				}

				fmt.Printf(" - %s: %s%s\n", algoName, algo.Description(), defaultMarker)
			}
		},
	}

	//* DIsplay Methods Command */
	methodsCommand := &cobra.Command{
		Use:   "methods",
		Short: "List key derivation methods",
		Long:  "Display the list of available methods for key derivation.",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Implemented methods:")

			for _, methodName := range keygen.GetImplementedMethodNames() {
				method := keygen.ImplementedMethods[methodName]
				defaultMarker := ""
				if methodName == keygen.DefaultMethod.Name() {
					defaultMarker = " (default)"
				}

				fmt.Printf(" - %s: %s%s\n", methodName, method.Description(), defaultMarker)
			}
		},
	}

	//* Display Version Command */
	versionCommand := &cobra.Command{
		Use:   "version",
		Short: "Display program version",
		Long:  "Display the current version of this program.",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			utils.PrintVersion(appVersion)
		},
	}

	//* Run Root Command */
	rootCommand.AddCommand(keygenCommand, encryptCommand, decryptCommand, algosCommand, methodsCommand, versionCommand)
	if err := rootCommand.Execute(); err != nil {
		log.Fatal(err)
	}
}
