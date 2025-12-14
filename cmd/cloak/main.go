package main

import (
	"crypto/rand"
	"fmt"
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
		//* Root Command Args and Flags */
		rootDisplayVersion bool // whether to display program version

		//* Keygen Command Args and Flags */
		keygenFuncName string // name of key derivation function to use
		keygenPassword string // password for key generation

		//* Encrypt Command Args and Flags */
		encryptAlgorithmName  string // name of algorithm used for encryption
		encryptPassword       string // password to be used for encryption
		encryptForceOverwrite bool   // whether to automatically overwrite output file
		encryptRemoveOriginal bool   // whether to remove the source file after encryption

		//* Decrypt Command Args and Flags */
		decryptAlgorithmName  string // name of algorithm used for decryption
		decryptPassword       string // password to be used for decryption
		decryptForceOverwrite bool   // whether to automatically overwrite output file
		decryptRemoveOriginal bool   // whether to remove the source file after decryption
	)

	//* Root Command */
	rootCommand := &cobra.Command{
		Use:   "cloak",
		Short: "Cloak allows you to encrypt or decrypt files.",
		Run: func(cmd *cobra.Command, args []string) {
			// display program version and exit if version flag is present
			if rootDisplayVersion {
				utils.PrintVersion(appVersion)
				os.Exit(0)
			}

			// display help and exit if no args were provided instead
			if len(args) == 0 {
				_ = cmd.Help()
				os.Exit(0)
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
		Long:  "Generate a static cryptographic key that can be used to encrypt and decrypt files, and save it to a file.",
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

			// check key derivation function name
			keygen, ok := keygen.Implemented[keygenFuncName]
			if !ok {
				fmt.Fprintf(os.Stderr, "unsupported key derivation function \"%s\"\n", keygenFuncName)
				os.Exit(1)
			}

			// check password
			if keygenPassword == "" {
				keygenPassword = utils.RequestUserPassword()
			} else {
				if !utils.ValidatePassword(keygenPassword) {
					fmt.Fprintf(os.Stderr, "invalid password\n")
					os.Exit(1)
				}
			}

			// generate random salt for key derivation
			salt := make([]byte, 16)
			if _, err := rand.Read(salt); err != nil {
				fmt.Fprintf(os.Stderr, "error generating random salt: %v\n", err)
			}

			// derive cryptographic key
			key, err := keygen.DeriveKey(keygenPassword, salt)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error generating key: %v\n", err)
				os.Exit(1)
			}

			// open output file
			outputFile, err := os.Create(outputFilePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error writing to output file \"%s\": %v\n", outputFilePath, err)
				os.Exit(1)
			}
			defer outputFile.Close()

			// write key to output file
			if _, err := outputFile.Write(key); err != nil {
				fmt.Fprintf(os.Stderr, "error writing key to output file: %v", err)
			}
		},
	}
	keygenCommand.Flags().StringVarP(&keygenFuncName, "function", "f", keygen.Default.Name(), "key derivation function")
	keygenCommand.Flags().StringVarP(&keygenPassword, "password", "p", "", "password for key generation")

	//* Encrypt Command */
	encryptCommand := &cobra.Command{
		Use:   "enc input output",
		Short: "Encrypt files",
		Long:  "Encrypt the file provided as input with the algorithm specified after the optional -x flag and write the result to the output file path. If the optional -r flag is passed, the source file is then deleted.",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			// read args
			inputFilePath := args[0]
			outputFilePath := args[1]

			// check that input file exists
			inputFileExists, err := utils.FileExists(inputFilePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "input path error: %v\n", err)
				os.Exit(1)
			}
			if !inputFileExists {
				fmt.Fprintf(os.Stderr, "input file \"%s\" does not exist\n", inputFilePath)
				os.Exit(1)
			}

			// check that output file does not already exist, eventually asking the user if he wants to overwrite it
			outputFileExists, err := utils.FileExists(outputFilePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "output path error: %v\n", err)
				os.Exit(1)
			}
			if outputFileExists && !encryptForceOverwrite && !utils.ConfirmOverwrite(outputFilePath) {
				fmt.Fprintf(os.Stderr, "operation cancelled by user\n")
				os.Exit(1)
			}

			// check crypto algorithm
			algo, ok := algos.Implemented[encryptAlgorithmName]
			if !ok {
				fmt.Fprintf(os.Stderr, "unsupported crypto algorithm \"%s\"\n", encryptAlgorithmName)
				os.Exit(1)
			}

			// check password
			if encryptPassword == "" {
				encryptPassword = utils.RequestUserPassword()
			} else {
				if !utils.ValidatePassword(encryptPassword) {
					fmt.Fprintf(os.Stderr, "invalid password\n")
					os.Exit(1)
				}
			}

			// open input file
			inputFile, err := os.Open(inputFilePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error opening input file \"%s\": %v\n", inputFilePath, err)
				os.Exit(1)
			}
			defer inputFile.Close()

			// open output file
			outputFile, err := os.Create(outputFilePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error writing to output file \"%s\": %v\n", outputFilePath, err)
				os.Exit(1)
			}
			defer outputFile.Close()

			// encrypt input file
			if err := algo.EncryptWithPsw(inputFile, outputFile, encryptPassword); err != nil {
				fmt.Fprintf(os.Stderr, "error encrypting input file: %v\n", err)
				os.Exit(1)
			}

			// remove original file if requested
			if encryptRemoveOriginal {
				if err := os.Remove(inputFilePath); err != nil {
					fmt.Fprintf(os.Stderr, "error removing input file \"%s\": %v\n", inputFilePath, err)
					os.Exit(1)
				}
			}
		},
	}
	encryptCommand.Flags().StringVarP(&encryptAlgorithmName, "algorithm", "a", algos.Default.Name(), "encryption algorithm")
	encryptCommand.Flags().StringVarP(&encryptPassword, "password", "p", "", "password used for encryption")
	encryptCommand.Flags().BoolVarP(&encryptForceOverwrite, "force", "f", false, "overwrite output file without asking")
	encryptCommand.Flags().BoolVarP(&encryptRemoveOriginal, "replace", "r", false, "remove source file after encryption")

	//* Decrypt Command */
	decryptCommand := &cobra.Command{
		Use:   "dec input output",
		Short: "Decrypt files",
		Long:  "Decrypt the file provided as input with the algorithm specified after the optional -x flag and write the result to the output file path. If the optional -r flag is passed, the source file is then deleted.",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			// read args
			inputFilePath := args[0]
			outputFilePath := args[1]

			// check that input file exists
			inputFileExists, err := utils.FileExists(inputFilePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "input path error: %v\n", err)
				os.Exit(1)
			}
			if !inputFileExists {
				fmt.Fprintf(os.Stderr, "input file \"%s\" does not exist\n", inputFilePath)
				os.Exit(1)
			}

			// check that output file does not already exist, eventually asking the user if he wants to overwrite it
			outputFileExists, err := utils.FileExists(outputFilePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "output path error: %v\n", err)
				os.Exit(1)
			}
			if outputFileExists && !decryptForceOverwrite && !utils.ConfirmOverwrite(outputFilePath) {
				fmt.Fprintf(os.Stderr, "operation cancelled by user\n")
				os.Exit(1)
			}

			// check crypto algorithm
			algo, ok := algos.Implemented[decryptAlgorithmName]
			if !ok {
				fmt.Fprintf(os.Stderr, "unsupported crypto algorithm \"%s\"\n", decryptAlgorithmName)
				os.Exit(1)
			}

			// check password
			if decryptPassword == "" {
				decryptPassword = utils.RequestUserPassword()
			} else {
				if !utils.ValidatePassword(decryptPassword) {
					fmt.Fprintf(os.Stderr, "invalid password\n")
					os.Exit(1)
				}
			}

			// open input file
			inputFile, err := os.Open(inputFilePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error opening input file \"%s\": %v\n", inputFilePath, err)
				os.Exit(1)
			}
			defer inputFile.Close()

			// open output file
			outputFile, err := os.Create(outputFilePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error writing to output file \"%s\": %v\n", outputFilePath, err)
				os.Exit(1)
			}
			defer outputFile.Close()

			// decrypt input file
			if err := algo.DecryptWithPsw(inputFile, outputFile, decryptPassword); err != nil {
				fmt.Fprintf(os.Stderr, "error decrypting input file: %v\n", err)
				os.Exit(1)
			}

			// remove original file if requested
			if decryptRemoveOriginal {
				if err := os.Remove(inputFilePath); err != nil {
					fmt.Fprintf(os.Stderr, "error removing input file \"%s\": %v\n", inputFilePath, err)
					os.Exit(1)
				}
			}
		},
	}
	decryptCommand.Flags().StringVarP(&decryptAlgorithmName, "algorithm", "a", algos.Default.Name(), "decryption algorithm")
	decryptCommand.Flags().StringVarP(&decryptPassword, "password", "p", "", "password used for decryption")
	decryptCommand.Flags().BoolVarP(&decryptForceOverwrite, "force", "f", false, "overwrite output file without asking")
	decryptCommand.Flags().BoolVarP(&decryptRemoveOriginal, "replace", "r", false, "remove source file after decryption")

	//* Display Algos Command */
	displayAlgosCommand := &cobra.Command{
		Use:   "algos",
		Short: "List implemented crypto algorithms",
		Long:  "Display a list of implemented cryptographic algorithms for encryption and decryption.",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Implemented algorithms:")

			for _, algoName := range algos.GetImplementedAlgoNames() {
				algo := algos.Implemented[algoName]
				defaultMarker := ""
				if algoName == algos.Default.Name() {
					defaultMarker = " (default)"
				}

				fmt.Printf(" - %s: %s%s\n", algoName, algo.Description(), defaultMarker)
			}
		},
	}

	//* Display Version Command */
	displayVersionCommand := &cobra.Command{
		Use:   "version",
		Short: "Display program version",
		Long:  "Display the current version of this program.",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			utils.PrintVersion(appVersion)
		},
	}

	//* Run Root Command */
	rootCommand.AddCommand(keygenCommand, encryptCommand, decryptCommand, displayAlgosCommand, displayVersionCommand)
	if err := rootCommand.Execute(); err != nil {
		log.Fatal(err)
	}
}
