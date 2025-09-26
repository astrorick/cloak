package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"slices"
	"strings"

	"github.com/astrorick/cloak/pkg/algos"
	"github.com/astrorick/cloak/pkg/utils"
	"github.com/astrorick/semantika"
	"github.com/spf13/cobra"
)

//* Cloak Logic */

type CryptoAlgorithm interface {
	Name() string
	Description() string
	Encrypt(input io.Reader, output io.Writer, psw string) error
	Decrypt(input io.Reader, output io.Writer, psw string) error
}

var implementedAlgorithms = map[string]CryptoAlgorithm{
	//* Advanced Encryption Standard (AES) Family */
	"aesgcm128": algos.NewAESGCM128(),
	"aesgcm192": algos.NewAESGCM192(),
	"aesgcm256": algos.NewAESGCM256(),

	//* ChaCha20 Family */
	"chacha20poly1305": algos.NewChaCha20Poly1305(),
}
var defaultAlgorithm = implementedAlgorithms["aesgcm256"]

//* CLI Logic */

func main() {
	//* Program Version */
	appVersion := &semantika.Version{
		Major: 0,
		Minor: 4,
		Patch: 0,
	}

	//* Command Line Args and Flags Parsing */
	var (
		displayVersion bool // whether to display program version

		encryptionAlgorithmName  string // name of algorithm used for encryption
		encryptionForceOverwrite bool   // whether to automatically overwrite output file
		encryptionReplace        bool   // whether to remove the source file after encryption

		decryptionAlgorithmName  string // name of algorithm used for decryption
		decryptionForceOverwrite bool   // whether to automatically overwrite output file
		decryptionReplace        bool   // whether to remove the source file after decryption
	)
	rootCommand := &cobra.Command{
		Use:   "cloak",
		Short: "Cloak allows you to encrypt or decrypt files.",
		Run: func(cmd *cobra.Command, args []string) {
			// display program version and exit if version flag is present
			if displayVersion {
				fmt.Printf("Cloak v%s by Astrorick.\n", appVersion.String())
				os.Exit(0)
			}

			// display help and exit if no args were provided
			if len(args) == 0 {
				_ = cmd.Help()
				os.Exit(0)
			}
		},
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true, // this disables the "completion" command which is shown dy default
		},
	}
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
			algo, ok := implementedAlgorithms[encryptionAlgorithmName]
			if !ok {
				fmt.Printf("Unsupported encryption algorithm \"%s\". Implemented algorithms: (%s).", encryptionAlgorithmName, strings.Join(getAlgorithmNames(), ", "))
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
			algo, ok := implementedAlgorithms[decryptionAlgorithmName]
			if !ok {
				fmt.Printf("Unsupported decryption algorithm \"%s\". Implemented algorithms: (%s).", decryptionAlgorithmName, strings.Join(getAlgorithmNames(), ", "))
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
	displayAlgosCommand := &cobra.Command{
		Use:   "algos",
		Short: "List implemented algorithms",
		Long:  "Display a list of implemented algorithms for encryption and decryption",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Implemented algorithms:")

			for _, algoName := range getAlgorithmNames() {
				algo := implementedAlgorithms[algoName]
				defaultMarker := ""
				if algoName == defaultAlgorithm.Name() {
					defaultMarker = " (default)"
				}

				fmt.Printf(" - %s: %s%s\n", algoName, algo.Description(), defaultMarker)
			}
		},
	}
	displayVersionCommand := &cobra.Command{
		Use:   "version",
		Short: "Display program version",
		Long:  "Display the current version of this program",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Cloak v%s by Astrorick.\n", appVersion.String())
		},
	}

	//* Register Flags and Commands */
	rootCommand.Flags().BoolVarP(&displayVersion, "version", "v", false, "program version")
	encryptCommand.Flags().StringVarP(&encryptionAlgorithmName, "algorithm", "x", defaultAlgorithm.Name(), fmt.Sprintf("encryption algorithm (%s)", strings.Join(getAlgorithmNames(), ", ")))
	encryptCommand.Flags().BoolVarP(&encryptionForceOverwrite, "force", "f", false, "overwrite output file without asking")
	encryptCommand.Flags().BoolVarP(&encryptionReplace, "replace", "r", false, "remove source file after encryption")
	decryptCommand.Flags().StringVarP(&decryptionAlgorithmName, "algorithm", "x", defaultAlgorithm.Name(), fmt.Sprintf("decryption algorithm (%s)", strings.Join(getAlgorithmNames(), ", ")))
	decryptCommand.Flags().BoolVarP(&decryptionForceOverwrite, "force", "f", false, "overwrite output file without asking")
	decryptCommand.Flags().BoolVarP(&decryptionReplace, "replace", "r", false, "remove source file after decryption")
	rootCommand.AddCommand(encryptCommand, decryptCommand, displayAlgosCommand, displayVersionCommand)

	//* Run Root Command */
	if err := rootCommand.Execute(); err != nil {
		log.Fatal(err)
	}
}

//* Auxiliary Functions */

// getAlgorithmNames returns a strings slice with the names of implemented algorithms
func getAlgorithmNames() []string {
	algoNames := make([]string, 0, len(implementedAlgorithms))
	for algoName := range implementedAlgorithms {
		algoNames = append(algoNames, algoName)
	}

	slices.Sort(algoNames)

	return algoNames
}
