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
		Minor: 7,
		Patch: 2,
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

			// if no subcommand is given, display help instead
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
		Long:  "Generate a static cryptographic key of fixed size that can be used to encrypt and decrypt files, and save it to the specified output location.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// read args
			outputFilePath := args[0]

			// check that output file does not already exist, and NEVER OVERWRITE
			outputFileExists, _, err := utils.FileExists(outputFilePath)
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
		Long:  "Generate one or more cryptographically random passwords using letters, digits, and the symbols " + pswgen.AllowedSymbols + ". Password length and number of generated passwords can be customized with the optional -l and -n flags.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// validate requested number of password
			if pswgenNumber < 1 {
				return fmt.Errorf("invalid number of passwords (must be at least 1, got %d)", pswgenNumber)
			}

			// generate and print passwords
			for range pswgenNumber {
				password, err := pswgen.GenerateRandomPassword(pswgenLength)
				if err != nil {
					return fmt.Errorf("error generating password: %w", err)
				}

				// print password to stdout
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

				// check that the key length is consistent
				if len(key) != 64 { //! this value is hardcoded for now
					return fmt.Errorf("invalid key file size (expected 64 bytes, got %d)", len(key))
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
					encryptPassword = utils.RequestUserPassword()
				}

				// derive encryption key from user password and salt
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

				// check that the key length is consistent
				if len(key) != 64 { //! this value is hardcoded for now
					return fmt.Errorf("invalid key file size (expected 64 bytes, got %d)", len(key))
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
					decryptPassword = utils.RequestUserPassword()
				}

				// derive decryption key from user password and salt
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

	//* Display Algos Command */
	algosCommand := &cobra.Command{
		Use:   "algos",
		Short: "List crypto algorithms",
		Long:  "Display the list of available cryptographic algorithms for encryption and decryption.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Implemented crypto algorithms for encryption/decryption:")

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
			fmt.Println("Implemented methods for key derivation:")

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
