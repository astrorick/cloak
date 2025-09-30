package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/astrorick/cloak/pkg/algos"
	"github.com/astrorick/cloak/pkg/utils"
	"github.com/astrorick/semantika"
	"github.com/spf13/cobra"
)

//* CLI Logic */

func main() {
	//* Program Version */
	appVersion := &semantika.Version{
		Major: 0,
		Minor: 4,
		Patch: 0,
	}

	var (
		//* Root Command Args and Flags */
		displayVersion bool // whether to display program version

		//* Encrypt Command Args and Flags */
		encryptionAlgorithmName   string // name of algorithm used for encryption
		encryptionPassword        string // password to be used for encryption
		encryptionForceOverwrite  bool   // whether to automatically overwrite output file
		encryptionReplaceOriginal bool   // whether to remove the source file after encryption

		//* Decrypt Command Args and Flags */
		decryptionAlgorithmName   string // name of algorithm used for decryption
		decryptionPassword        string // password to be used for decryption
		decryptionForceOverwrite  bool   // whether to automatically overwrite output file
		decryptionReplaceOriginal bool   // whether to remove the source file after decryption
	)

	//* Root Command */
	rootCommand := &cobra.Command{
		Use:   "cloak",
		Short: "Cloak allows you to encrypt or decrypt files.",
		Run: func(cmd *cobra.Command, args []string) {
			// display program version and exit if version flag is present
			if displayVersion {
				utils.PrintAppVersion(appVersion)
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
	rootCommand.Flags().BoolVarP(&displayVersion, "version", "v", false, "program version")

	//* Encrypt Command */
	encryptCommand := &cobra.Command{
		Use:   "enc input output",
		Short: "Encrypt files",
		Long:  "Encrypt the file provided as input with the algorithm specified after the optional -x flag and write the result to the output file path. If the optional -r flag is passed, the source file is then deleted.",
		Run: func(cmd *cobra.Command, args []string) {
			// check arguments
			if len(args) != 2 {
				fmt.Fprintf(os.Stderr, "invalid command usage\n")
				os.Exit(1)
			}

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
			if outputFileExists && !encryptionForceOverwrite && !utils.ConfirmOverwrite(outputFilePath) {
				fmt.Fprintf(os.Stderr, "operation cancelled by user\n")
				os.Exit(1)
			}

			// check crypto algorithm
			algo, ok := algos.Implemented[encryptionAlgorithmName]
			if !ok {
				fmt.Fprintf(os.Stderr, "unsupported crypto algorithm \"%s\"\n", encryptionAlgorithmName)
				os.Exit(1)
			}

			// check password
			if encryptionPassword == "" {
				encryptionPassword = utils.RequestUserPassword()
			} else {
				if !utils.ValidatePassword(encryptionPassword) {
					fmt.Fprintf(os.Stderr, "invalid encryption password\n")
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
			if err := algo.EncryptWithPsw(inputFile, outputFile, encryptionPassword); err != nil {
				fmt.Fprintf(os.Stderr, "error encrypting input file: %v\n", err)
				os.Exit(1)
			}

			// remove original file if requested
			if encryptionReplaceOriginal {
				if err := os.Remove(inputFilePath); err != nil {
					fmt.Fprintf(os.Stderr, "error removing input file \"%s\": %v\n", inputFilePath, err)
					os.Exit(1)
				}
			}
		},
	}
	encryptCommand.Flags().StringVarP(&encryptionAlgorithmName, "algorithm", "x", algos.Default.Name(), fmt.Sprintf("encryption algorithm (%s)", strings.Join(algos.GetImplementedAlgoNames(), ", ")))
	encryptCommand.Flags().StringVarP(&encryptionPassword, "password", "p", "", "password used for encryption")
	encryptCommand.Flags().BoolVarP(&encryptionForceOverwrite, "force", "f", false, "overwrite output file without asking")
	encryptCommand.Flags().BoolVarP(&encryptionReplaceOriginal, "replace", "r", false, "remove source file after encryption")

	//* Decrypt Command */
	decryptCommand := &cobra.Command{
		Use:   "dec input output",
		Short: "Decrypt files",
		Long:  "Decrypt the file provided as input with the algorithm specified after the optional -x flag and write the result to the output file path. If the optional -r flag is passed, the source file is then deleted.",
		Run: func(cmd *cobra.Command, args []string) {
			// check arguments
			if len(args) != 2 {
				fmt.Fprintf(os.Stderr, "invalid command usage\n")
				os.Exit(1)
			}

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
			if outputFileExists && !decryptionForceOverwrite && !utils.ConfirmOverwrite(outputFilePath) {
				fmt.Fprintf(os.Stderr, "operation cancelled by user\n")
				os.Exit(1)
			}

			// check crypto algorithm
			algo, ok := algos.Implemented[decryptionAlgorithmName]
			if !ok {
				fmt.Fprintf(os.Stderr, "unsupported crypto algorithm \"%s\"\n", decryptionAlgorithmName)
				os.Exit(1)
			}

			// check password
			if decryptionPassword == "" {
				decryptionPassword = utils.RequestUserPassword()
			} else {
				if !utils.ValidatePassword(decryptionPassword) {
					fmt.Fprintf(os.Stderr, "invalid decryption password\n")
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
			if err := algo.DecryptWithPsw(inputFile, outputFile, decryptionPassword); err != nil {
				fmt.Fprintf(os.Stderr, "error decrypting input file: %v\n", err)
				os.Exit(1)
			}

			// remove original file if requested
			if decryptionReplaceOriginal {
				if err := os.Remove(inputFilePath); err != nil {
					fmt.Fprintf(os.Stderr, "error removing input file \"%s\": %v\n", inputFilePath, err)
					os.Exit(1)
				}
			}
		},
	}
	decryptCommand.Flags().StringVarP(&decryptionAlgorithmName, "algorithm", "x", algos.Default.Name(), fmt.Sprintf("decryption algorithm (%s)", strings.Join(algos.GetImplementedAlgoNames(), ", ")))
	decryptCommand.Flags().StringVarP(&decryptionPassword, "password", "p", "", "password used for decryption")
	decryptCommand.Flags().BoolVarP(&decryptionForceOverwrite, "force", "f", false, "overwrite output file without asking")
	decryptCommand.Flags().BoolVarP(&decryptionReplaceOriginal, "replace", "r", false, "remove source file after decryption")

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
			utils.PrintAppVersion(appVersion)
		},
	}

	//* Run Root Command */
	rootCommand.AddCommand(encryptCommand, decryptCommand, displayAlgosCommand, displayVersionCommand)
	if err := rootCommand.Execute(); err != nil {
		log.Fatal(err)
	}
}
