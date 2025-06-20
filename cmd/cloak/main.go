package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"

	"github.com/astrorick/semantika"
	"github.com/spf13/cobra"
)

type Cloak struct {
	inputFilePath  string
	outputFilePath string

	cryptoAlgorithm string
	replaceMode     bool
}

// Encrypt encodes the input file with the specified algorithm and writes the result to the output file.
func (clk *Cloak) Encrypt() error {
	/*
		Program logic:
			1. ask user for psw
			2. read input file
			3. encrypt input file with encryption alg and psw
			4. save to output file
			5. if replace mode, delete input file
			6. return
	*/

	fmt.Printf("Encrypting \"%s\" to \"%s\" using %s. ", clk.inputFilePath, clk.outputFilePath, clk.cryptoAlgorithm)
	if clk.replaceMode {
		fmt.Println("The original file is deleted.")
	} else {
		fmt.Println("The original file is kept.")
	}

	return nil
}

// Decrypt decodes the input file with the specified algorithm and writes the result to the output file.
func (clk *Cloak) Decrypt() error {
	/*
		Program logic:
			1. ask user for psw
			2. take input file
			3. decrypt input file with encryption alg and psw
			4. save to output file
			5. if replace mode, delete input file (CHECK FOR SUCCESS)
			6. return
	*/

	fmt.Printf("Decrypting \"%s\" to \"%s\" using %s. ", clk.inputFilePath, clk.outputFilePath, clk.cryptoAlgorithm)
	if clk.replaceMode {
		fmt.Println("The original file is deleted.")
	} else {
		fmt.Println("The original file is kept.")
	}

	return nil
}

// program entry point
func main() {
	//* Program Version */
	appVersion := &semantika.Version{
		Major: 0,
		Minor: 2,
		Patch: 0,
	}

	//* Default Program Config */
	clk := &Cloak{}

	//* Command Line Args and Flags Parsing */
	var (
		displayVersion bool // whether to display program version

		encryptionAlgorithm string // algorithm used for encryption
		decryptionAlgorithm string // algorithm used for decryption
		encryptionReplace   bool   // whether to remove the original file after encryption
		decryptionReplace   bool   // whether to remove the original file after decryption

		implementedAlgorithms = []string{"aes128", "aes192", "aes256"} // all implemented algorithms for encryption and decryption
	)
	rootCommand := &cobra.Command{ // cloak
		Use:   "cloak",
		Short: "Cloak lets you encrypt and decrypt files.",
		Run: func(cmd *cobra.Command, args []string) {
			// display program version and exit if flag set
			if displayVersion {
				fmt.Printf("Cloak v%s by Astrorick\n", appVersion.String())
				os.Exit(0)
			}

			// display help if no args provided
			if len(args) == 0 {
				_ = cmd.Help()
				os.Exit(0)
			}
		},
		CompletionOptions: cobra.CompletionOptions{
			// this disables the "completion" command which is shown dy default
			DisableDefaultCmd: true,
		},
	}
	encryptCommand := &cobra.Command{ // cloak enc
		Use:   "enc input output [-x algorithm] [-r]",
		Short: "Encrypt files",
		Long:  "Encrypt the file provided as input with the algorithm specified after the optional -x flag (defaults to aes256). Write the result to the output file. If the optional -r flag is passed, the original file is then deleted.",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			// check if input file inputExists
			inputExists, err := fileExists(args[0])
			if err != nil {
				log.Fatal(err)
			}
			if !inputExists {
				log.Fatalf("Input file \"%s\" does not exist.\n", args[0])
			}

			// check that output file does not already exist
			outputExists, err := fileExists(args[1])
			if err != nil {
				log.Fatal(err)
			}
			if outputExists && !confirmOverwrite(args[1]) {
				fmt.Println("Operation cancelled by user.")
				os.Exit(0)
			}

			// check crypto algorithm
			if !slices.Contains(implementedAlgorithms, encryptionAlgorithm) {
				fmt.Printf("Unsupported encryption algorithm \"%s\". Implemented algorithms: (%s).", encryptionAlgorithm, strings.Join(implementedAlgorithms, ", "))
				return
			}

			// generate config from args and flags
			clk.inputFilePath = args[0]
			clk.outputFilePath = args[1]
			clk.cryptoAlgorithm = encryptionAlgorithm
			clk.replaceMode = encryptionReplace

			if err := clk.Encrypt(); err != nil {
				log.Fatal(err)
			}
		},
	}
	decryptCommand := &cobra.Command{ // cloak dec
		Use:   "dec input output [-x algorithm] [-r]",
		Short: "Decrypt files",
		Long:  "Decrypt the file provided as input with the algorithm specified after the optional -x flag (defaults to aes256). Write the result to the output file. If the optional -r flag is passed, the original file is then deleted.",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			// check if input file inputExists
			inputExists, err := fileExists(args[0])
			if err != nil {
				log.Fatal(err)
			}
			if !inputExists {
				log.Fatalf("Input file \"%s\" does not exist.\n", args[0])
			}

			// check that output file does not already exist
			outputExists, err := fileExists(args[1])
			if err != nil {
				log.Fatal(err)
			}
			if outputExists && !confirmOverwrite(args[1]) {
				fmt.Println("Operation cancelled by user.")
				os.Exit(0)
			}

			// check crypto algorithm
			if !slices.Contains(implementedAlgorithms, decryptionAlgorithm) {
				fmt.Printf("Unsupported decryption algorithm \"%s\". Implemented algorithms: (%s).", decryptionAlgorithm, strings.Join(implementedAlgorithms, ", "))
				return
			}

			// generate config from args and flags
			clk.inputFilePath = args[0]
			clk.outputFilePath = args[1]
			clk.cryptoAlgorithm = decryptionAlgorithm
			clk.replaceMode = decryptionReplace

			if err := clk.Decrypt(); err != nil {
				log.Fatal(err)
			}
		},
	}
	displayAlgosCommand := &cobra.Command{ // cloak algos
		Use:   "algos",
		Short: "Display implemented algorithms",
		Long:  "Display a list of implemented algorithms for encryption and decryption",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Implemented algorithms: (%s)\n", strings.Join(implementedAlgorithms, ", "))
		},
	}
	displayVersionCommand := &cobra.Command{ // cloak ver
		Use:   "version",
		Short: "Display program version",
		Long:  "Display the current version of this program",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Cloak v%s by Astrorick\n", appVersion.String())
		},
	}
	rootCommand.Flags().BoolVarP(&displayVersion, "version", "v", false, "Display program version")
	encryptCommand.Flags().StringVarP(&encryptionAlgorithm, "algorithm", "x", "aes256", fmt.Sprintf("Encryption algorithm (%s)", strings.Join(implementedAlgorithms, ", ")))
	encryptCommand.Flags().BoolVarP(&encryptionReplace, "replace", "r", false, "Remove original file after encryption")
	decryptCommand.Flags().StringVarP(&decryptionAlgorithm, "algorithm", "x", "aes256", fmt.Sprintf("Decryption algorithm (%s)", strings.Join(implementedAlgorithms, ", ")))
	decryptCommand.Flags().BoolVarP(&decryptionReplace, "replace", "r", false, "Remove original file after decryption")
	rootCommand.AddCommand(encryptCommand, decryptCommand, displayAlgosCommand, displayVersionCommand)

	//* Run Program */
	if err := rootCommand.Execute(); err != nil {
		log.Fatal(err)
	}
}

func fileExists(filePath string) (bool, error) {
	_, err := os.Stat(filePath)

	if err == nil {
		return true, nil
	}

	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}

	return false, err
}

func confirmOverwrite(filePath string) bool {
	positiveAnswers := []string{"y", "yes", ""}
	negativeAnswers := []string{"n", "no"}
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("Output file \"%s\" already exists. Overwrite? (Y/n): ", filePath)

	// keep asking the user until they provides an acceptable answer
	for {
		userInput, _ := reader.ReadString('\n')
		userAnswer := strings.ToLower(strings.TrimSpace(userInput))

		// check if answer is negative
		if slices.Contains(negativeAnswers, userAnswer) {
			return false
		}

		// check if answer is positive
		if slices.Contains(positiveAnswers, userAnswer) {
			return true
		}

		// repeat question
		fmt.Print("Invalid answer. Overwrite? (Y/n): ")
	}
}
