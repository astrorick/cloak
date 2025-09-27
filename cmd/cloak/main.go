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
		//* Root Command Flags */
		displayVersion bool // whether to display program version

		//* Encrypt Command Flags */
		encryptionAlgorithmName  string // name of algorithm used for encryption
		encryptionForceOverwrite bool   // whether to automatically overwrite output file
		encryptionReplace        bool   // whether to remove the source file after encryption

		//* Decrypt Command Flags */
		decryptionAlgorithmName  string // name of algorithm used for decryption
		decryptionForceOverwrite bool   // whether to automatically overwrite output file
		decryptionReplace        bool   // whether to remove the source file after decryption
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
			// check for correct number of arguments
			if len(args) != 2 {
				_ = cmd.Help()
				os.Exit(1)
			}

			// read input and output file paths from arguments
			inputFilePath := args[0]
			outputFilePath := args[1]

			// check that input file exists
			inputFileExists, err := utils.FileExists(inputFilePath)
			if err != nil {
				log.Fatal(err)
			}
			if !inputFileExists {
				log.Fatalf("Input file \"%s\" does not exist.\n", inputFilePath)
			}

			// check that output file does not already exist
			outputFileExists, err := utils.FileExists(outputFilePath)
			if err != nil {
				log.Fatal(err)
			}
			if outputFileExists && !encryptionForceOverwrite && !utils.ConfirmOverwrite(outputFilePath) {
				fmt.Println("Operation cancelled by user.")
				os.Exit(0)
			}

			// check crypto algorithm
			algo, ok := algos.Implemented[encryptionAlgorithmName]
			if !ok {
				fmt.Printf("Unsupported encryption algorithm \"%s\". Implemented algorithms: (%s).", encryptionAlgorithmName, strings.Join(algos.GetImplementedAlgoNames(), ", "))
				os.Exit(1)
			}

			// open input file
			in, err := os.Open(inputFilePath)
			if err != nil {
				log.Fatal(err)
			}
			defer in.Close()

			// open output file
			out, err := os.Create(outputFilePath)
			if err != nil {
				log.Fatal(err)
			}
			defer out.Close()

			// encrypt
			if err := algo.Encrypt(in, out, utils.RequestUserPassword()); err != nil {
				_ = os.Remove(outputFilePath)
				log.Fatal(err)
			}

			// remove original file if flag was set
			if encryptionReplace {
				if err := os.Remove(inputFilePath); err != nil {
					log.Fatal(err)
				}
			}
		},
	}
	encryptCommand.Flags().StringVarP(&encryptionAlgorithmName, "algorithm", "x", algos.Default.Name(), fmt.Sprintf("encryption algorithm (%s)", strings.Join(algos.GetImplementedAlgoNames(), ", ")))
	encryptCommand.Flags().BoolVarP(&encryptionForceOverwrite, "force", "f", false, "overwrite output file without asking")
	encryptCommand.Flags().BoolVarP(&encryptionReplace, "replace", "r", false, "remove source file after encryption")

	//* Decrypt Command */
	decryptCommand := &cobra.Command{
		Use:   "dec input output",
		Short: "Decrypt files",
		Long:  "Decrypt the file provided as input with the algorithm specified after the optional -x flag and write the result to the output file path. If the optional -r flag is passed, the source file is then deleted.",
		Run: func(cmd *cobra.Command, args []string) {
			// check for correct number of arguments
			if len(args) != 2 {
				_ = cmd.Help()
				os.Exit(1)
			}

			// read input and output file paths from arguments
			inputFilePath := args[0]
			outputFilePath := args[1]

			// check that input file exists
			inputFileExists, err := utils.FileExists(inputFilePath)
			if err != nil {
				log.Fatal(err)
			}
			if !inputFileExists {
				log.Fatalf("Input file \"%s\" does not exist.\n", inputFilePath)
			}

			// check that output file does not already exist
			outputFileExists, err := utils.FileExists(outputFilePath)
			if err != nil {
				log.Fatal(err)
			}
			if outputFileExists && !decryptionForceOverwrite && !utils.ConfirmOverwrite(outputFilePath) {
				fmt.Println("Operation cancelled by user.")
				os.Exit(0)
			}

			// check crypto algorithm
			algo, ok := algos.Implemented[decryptionAlgorithmName]
			if !ok {
				fmt.Printf("Unsupported decryption algorithm \"%s\". Implemented algorithms: (%s).", decryptionAlgorithmName, strings.Join(algos.GetImplementedAlgoNames(), ", "))
				os.Exit(1)
			}

			// open input file
			in, err := os.Open(inputFilePath)
			if err != nil {
				log.Fatal(err)
			}
			defer in.Close()

			// open output file
			out, err := os.Create(outputFilePath)
			if err != nil {
				log.Fatal(err)
			}
			defer out.Close()

			// decrypt
			if err := algo.Decrypt(in, out, utils.RequestUserPassword()); err != nil {
				_ = os.Remove(outputFilePath)
				log.Fatal(err)
			}

			// remove original file if flag was set
			if decryptionReplace {
				if err := os.Remove(inputFilePath); err != nil {
					log.Fatal(err)
				}
			}
		},
	}
	decryptCommand.Flags().StringVarP(&decryptionAlgorithmName, "algorithm", "x", algos.Default.Name(), fmt.Sprintf("decryption algorithm (%s)", strings.Join(algos.GetImplementedAlgoNames(), ", ")))
	decryptCommand.Flags().BoolVarP(&decryptionForceOverwrite, "force", "f", false, "overwrite output file without asking")
	decryptCommand.Flags().BoolVarP(&decryptionReplace, "replace", "r", false, "remove source file after decryption")

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
