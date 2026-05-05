package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/astrorick/cloak/pkg/algos"
	"github.com/astrorick/cloak/pkg/keygen"
	"github.com/astrorick/cloak/pkg/pswgen"
	"github.com/astrorick/cloak/pkg/utils"
	"github.com/astrorick/semantika"
	"github.com/spf13/cobra"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	//* Program Version */
	appVersion := &semantika.Version{
		Major: 0,
		Minor: 6,
		Patch: 1,
	}

	var (
		//* Root Command Flags */
		rootDisplayVersion bool // whether to display program version and exit

		//* Pswgen Command Flags */
		pswgenLength int // length of each generated password
		pswgenNumber int // number of passwords to generate

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
		Use:           "cloak",
		Short:         "Cloak allows you to encrypt and decrypt files using a cryptographic key or a password.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// if version flag is passed, display program version and exit
			if rootDisplayVersion {
				utils.PrintVersion(appVersion)
				return nil
			}

			// if no subcommand is given, display help
			return cmd.Help()
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
		RunE: func(cmd *cobra.Command, args []string) error {
			// read args
			outputFilePath := args[0]

			// check that output file does not already exist, but NEVER OVERWRITE
			outputFileExists, err := utils.FileExists(outputFilePath)
			if err != nil {
				return fmt.Errorf("output path error: %w", err)
			}
			if outputFileExists {
				return fmt.Errorf("output file \"%s\" already exists, aborting", outputFilePath)
			}

			// generate random cryptographic key
			key, err := keygen.GenerateRandomKey()
			if err != nil {
				return fmt.Errorf("error generating random key: %w", err)
			}

			// open output file
			outputFile, err := os.Create(outputFilePath)
			if err != nil {
				return fmt.Errorf("error creating output file: %w", err)
			}
			defer outputFile.Close()

			// write key to output file
			if _, err := outputFile.Write(key); err != nil {
				return fmt.Errorf("error writing to output file: %w", err)
			}

			return nil
		},
	}

	//* Pswgen Command */
	pswgenCommand := &cobra.Command{
		Use:   "pswgen",
		Short: "Generate random passwords",
		Long:  "Generate one or more cryptographically random passwords using printable ASCII characters. The password length and number of passwords can be customized with the optional -l and -n flags.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// validate password length (minimum 8, matching utils.ValidatePassword)
			if pswgenLength < 8 {
				return fmt.Errorf("invalid password length (must be at least 8, got %d)", pswgenLength)
			}

			// validate number of passwords
			if pswgenNumber < 1 {
				return fmt.Errorf("invalid number of passwords (must be at least 1, got %d)", pswgenNumber)
			}

			// generate and print passwords
			for i := 0; i < pswgenNumber; i++ {
				password, err := pswgen.GenerateRandomPassword(pswgenLength)
				if err != nil {
					return fmt.Errorf("error generating password: %w", err)
				}
				fmt.Println(password)
			}

			return nil
		},
	}
	pswgenCommand.Flags().IntVarP(&pswgenLength, "length", "l", 32, "length of each generated password")
	pswgenCommand.Flags().IntVarP(&pswgenNumber, "number", "n", 1, "number of passwords to generate")

	//* Encrypt Command */
	encryptCommand := &cobra.Command{
		Use:   "encrypt input output",
		Short: "Encrypt files",
		Long:  "Encrypt the file provided as input with the algorithm specified after the optional -a flag and write the result to the output file path. Either a cryptographic key file or a password can be used for encryption. If the optional -d flag is passed, the source file is then deleted.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// read input and output file paths from args
			inputFilePath := args[0]
			outputFilePath := args[1]

			// check chosen crypto algorithm
			algo, ok := algos.ImplementedAlgos[encryptAlgorithmName]
			if !ok {
				return fmt.Errorf("unsupported crypto algorithm \"%s\"", encryptAlgorithmName)
			}

			// check that the input file exists and open it
			inputFileExists, err := utils.FileExists(inputFilePath)
			if err != nil {
				return fmt.Errorf("input path error: %w", err)
			}
			if !inputFileExists {
				return fmt.Errorf("input file \"%s\" does not exist", inputFilePath)
			}
			inputFile, err := os.Open(inputFilePath)
			if err != nil {
				return fmt.Errorf("error opening input file \"%s\": %w", inputFilePath, err)
			}
			defer inputFile.Close()

			// check that the output file does not already exist, eventually asking the user if he wants to overwrite it, and create it
			outputFileExists, err := utils.FileExists(outputFilePath)
			if err != nil {
				return fmt.Errorf("output path error: %w", err)
			}
			if outputFileExists && !encryptForceOverwrite && !utils.ConfirmOverwrite(outputFilePath) {
				return errors.New("operation cancelled by user")
			}
			outputFile, err := os.Create(outputFilePath)
			if err != nil {
				return fmt.Errorf("error creating output file \"%s\": %w", outputFilePath, err)
			}
			defer outputFile.Close()

			// read entire input file
			plainBytes, err := io.ReadAll(inputFile)
			if err != nil {
				return fmt.Errorf("error reading input file \"%s\": %w", inputFilePath, err)
			}

			// load cryptographic key OR derive one from the user-provided password
			var salt, key []byte
			if encryptKeyFilePath != "" { //* load (and validate) key file
				// make sure the user did NOT specify both a key file and a password flag
				if encryptPassword != "" {
					return errors.New("flag error: flag -k can't be used with flag -p")
				}

				// check if the key file exists and open it
				keyFileExists, err := utils.FileExists(encryptKeyFilePath)
				if err != nil {
					return fmt.Errorf("key file path error: %w", err)
				}
				if !keyFileExists {
					return fmt.Errorf("key file \"%s\" does not exist", encryptKeyFilePath)
				}
				keyFile, err := os.Open(encryptKeyFilePath)
				if err != nil {
					return fmt.Errorf("error opening key file \"%s\": %w", encryptKeyFilePath, err)
				}
				defer keyFile.Close()

				// read key file
				key, err = io.ReadAll(keyFile)
				if err != nil {
					return fmt.Errorf("error reading key file \"%s\": %w", encryptKeyFilePath, err)
				}

				// check that the key length is consistent
				if len(key) != 64 {
					return fmt.Errorf("invalid key file size (expected 64 bytes, got %d)", len(key))
				}
			} else { //* derive key from password
				// check key derivation method
				method, ok := keygen.ImplementedMethods[encryptMethodName]
				if !ok {
					return fmt.Errorf("unsupported key derivation method \"%s\"", encryptMethodName)
				}

				// check if user provided a -p flag
				if encryptPassword != "" {
					// validate user-provided password (passed by -p flag)
					if !utils.ValidatePassword(encryptPassword) {
						return errors.New("invalid password")
					}
				} else {
					// request the user inputs its password from terminal
					encryptPassword = utils.RequestUserPassword()
				}

				// generate random salt for key derivation
				salt = make([]byte, 16)
				if _, err := rand.Read(salt); err != nil {
					return fmt.Errorf("error generating random salt: %w", err)
				}

				// derive encryption key from user password and salt
				key, err = method.DeriveKey(encryptPassword, salt)
				if err != nil {
					return fmt.Errorf("error generating cryptographic key: %w", err)
				}
			}

			// encrypt input file
			cipherBytes, err := algo.Encrypt(plainBytes, key)
			if err != nil {
				return fmt.Errorf("error encrypting input file: %w", err)
			}

			// write data to output file
			if encryptKeyFilePath != "" { //* key-based encryption: write nonce + ciphertext
				if _, err := outputFile.Write(cipherBytes); err != nil {
					return fmt.Errorf("error writing encrypted data to output file: %w", err)
				}
			} else { //* password-based encryption: write salt + nonce + ciphertext
				if _, err := outputFile.Write(salt); err != nil {
					return fmt.Errorf("error writing salt to output file: %w", err)
				}
				if _, err := outputFile.Write(cipherBytes); err != nil {
					return fmt.Errorf("error writing encrypted data to output file: %w", err)
				}
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

	//* Decrypt Command */
	decryptCommand := &cobra.Command{
		Use:   "decrypt input output",
		Short: "Decrypt files",
		Long:  "Decrypt the file provided as input with the algorithm specified after the optional -a flag and write the result to the output file path. Either a cryptographic key file or a password can be used for decryption. If the optional -d flag is passed, the source file is then deleted.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// read input and output file paths from args
			inputFilePath := args[0]
			outputFilePath := args[1]

			// check chosen crypto algorithm
			algo, ok := algos.ImplementedAlgos[decryptAlgorithmName]
			if !ok {
				return fmt.Errorf("unsupported crypto algorithm \"%s\"", decryptAlgorithmName)
			}

			// check that the input file exists and open it
			inputFileExists, err := utils.FileExists(inputFilePath)
			if err != nil {
				return fmt.Errorf("input path error: %w", err)
			}
			if !inputFileExists {
				return fmt.Errorf("input file \"%s\" does not exist", inputFilePath)
			}
			inputFile, err := os.Open(inputFilePath)
			if err != nil {
				return fmt.Errorf("error opening input file \"%s\": %w", inputFilePath, err)
			}
			defer inputFile.Close()

			// check that the output file does not already exist, eventually asking the user if he wants to overwrite it, and create it
			outputFileExists, err := utils.FileExists(outputFilePath)
			if err != nil {
				return fmt.Errorf("output path error: %w", err)
			}
			if outputFileExists && !decryptForceOverwrite && !utils.ConfirmOverwrite(outputFilePath) {
				return errors.New("operation cancelled by user")
			}
			outputFile, err := os.Create(outputFilePath)
			if err != nil {
				return fmt.Errorf("error creating output file \"%s\": %w", outputFilePath, err)
			}
			defer outputFile.Close()

			// read entire input file
			cipherBytes, err := io.ReadAll(inputFile)
			if err != nil {
				return fmt.Errorf("error reading input file \"%s\": %w", inputFilePath, err)
			}

			// load cryptographic key OR derive one from the user-provided password
			var salt, key []byte
			if decryptKeyFilePath != "" { //* load (and validate) key file
				// make sure the user did NOT specify both a key file and a password flag
				if decryptPassword != "" {
					return errors.New("flag error: flag -k can't be used with flag -p")
				}

				// check if the key file exists and open it
				keyFileExists, err := utils.FileExists(decryptKeyFilePath)
				if err != nil {
					return fmt.Errorf("key file path error: %w", err)
				}
				if !keyFileExists {
					return fmt.Errorf("key file \"%s\" does not exist", decryptKeyFilePath)
				}
				keyFile, err := os.Open(decryptKeyFilePath)
				if err != nil {
					return fmt.Errorf("error opening key file \"%s\": %w", decryptKeyFilePath, err)
				}
				defer keyFile.Close()

				// read key file
				key, err = io.ReadAll(keyFile)
				if err != nil {
					return fmt.Errorf("error reading key file \"%s\": %w", decryptKeyFilePath, err)
				}

				// check that the key length is consistent
				if len(key) != 64 {
					return fmt.Errorf("invalid key file size (expected 64 bytes, got %d)", len(key))
				}
			} else { //* derive key from password
				// check key derivation method
				method, ok := keygen.ImplementedMethods[decryptMethodName]
				if !ok {
					return fmt.Errorf("unsupported key derivation method \"%s\"", decryptMethodName)
				}

				// check if user provided a -p flag
				if decryptPassword != "" {
					// validate user-provided password (passed by -p flag)
					if !utils.ValidatePassword(decryptPassword) {
						return errors.New("invalid password")
					}
				} else {
					// request the user inputs its password from terminal
					decryptPassword = utils.RequestUserPassword()
				}

				// read salt for key derivation from file
				if len(cipherBytes) < 16 {
					return errors.New("invalid encrypted file format (too short for password-based decryption)")
				}
				salt = cipherBytes[:16]

				// derive decryption key from user password and salt
				key, err = method.DeriveKey(decryptPassword, salt)
				if err != nil {
					return fmt.Errorf("error generating cryptographic key: %w", err)
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
				return fmt.Errorf("error decrypting input file: %w", err)
			}

			// write data to output file
			if _, err := outputFile.Write(plainBytes); err != nil {
				return fmt.Errorf("error writing decrypted data to output file: %w", err)
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

	//* Display Algos Command */
	algosCommand := &cobra.Command{
		Use:   "algos",
		Short: "List crypto algorithms",
		Long:  "Display the list of available cryptographic algorithms for encryption and decryption.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Implemented algorithms:")

			for _, algoName := range algos.GetImplementedAlgoNames() {
				algo := algos.ImplementedAlgos[algoName]
				defaultMarker := ""
				if algoName == algos.DefaultAlgo.Name() {
					defaultMarker = " (default)"
				}

				fmt.Printf(" - %s: %s%s\n", algoName, algo.Description(), defaultMarker)
			}

			return nil
		},
	}

	//* DIsplay Methods Command */
	methodsCommand := &cobra.Command{
		Use:   "methods",
		Short: "List key derivation methods",
		Long:  "Display the list of available methods for key derivation.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Implemented methods:")

			for _, methodName := range keygen.GetImplementedMethodNames() {
				method := keygen.ImplementedMethods[methodName]
				defaultMarker := ""
				if methodName == keygen.DefaultMethod.Name() {
					defaultMarker = " (default)"
				}

				fmt.Printf(" - %s: %s%s\n", methodName, method.Description(), defaultMarker)
			}

			return nil
		},
	}

	//* Display Version Command */
	versionCommand := &cobra.Command{
		Use:   "version",
		Short: "Display program version",
		Long:  "Display the current version of this program.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			utils.PrintVersion(appVersion)
			return nil
		},
	}

	//* Run Root Command */
	rootCommand.AddCommand(keygenCommand, pswgenCommand, encryptCommand, decryptCommand, algosCommand, methodsCommand, versionCommand)
	return rootCommand.Execute()
}
