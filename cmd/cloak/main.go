package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"slices"
	"strings"
	"syscall"

	"github.com/astrorick/cloak/pkg/algos"
	"github.com/astrorick/semantika"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

//* Cloak Logic */

type Cloak struct {
	inputFilePath  string // path to input file
	outputFilePath string // path to output file

	cryptoAlgorithm CryptoAlgorithm // interface representation of the crypto algorithm to use
}

type CryptoAlgorithm interface {
	Name() string
	Seal(input io.Reader, output io.Writer, psw string) error
	Unseal(input io.Reader, output io.Writer, psw string) error
}

var defaultAlgorithm = "aes256" // change this to change default algorithm
var implementedAlgorithms = map[string]CryptoAlgorithm{
	//* Advanced Encryption Standard (AES) Family */
	"aes128": algos.NewAES128(),
	"aes192": algos.NewAES192(),
	"aes256": algos.NewAES256(),

	//* Blowfish Family */
	// TODO "blowfish": algos.NewBlowfish(),

	//* ChaCha20 Family */
	// TODO "chacha20": algos.NewChaCha20(),
	"chacha20poly1305": algos.NewChaCha20Poly1305(),

	//* Ascon Family */
	// TODO: "ascon": algos.NewAscon(),
}

// Encrypt encodes the input file with the specified algorithm and writes the result to the output file.
func (clk *Cloak) Encrypt(psw string) error {
	fmt.Printf("Encrypting \"%s\" to \"%s\" using %s.\n", clk.inputFilePath, clk.outputFilePath, clk.cryptoAlgorithm.Name())

	// open input file
	in, err := os.Open(clk.inputFilePath)
	if err != nil {
		return fmt.Errorf("error opening input file: %w", err)
	}
	defer in.Close()

	// open output file
	out, err := os.Create(clk.outputFilePath)
	if err != nil {
		return fmt.Errorf("error creating output file: %w", err)
	}
	defer out.Close()

	// encrypt file
	if err := clk.cryptoAlgorithm.Seal(in, out, psw); err != nil {
		return fmt.Errorf("error encrypting file: %w", err)
	}

	return nil
}

// Decrypt decodes the input file with the specified algorithm and writes the result to the output file.
func (clk *Cloak) Decrypt(psw string) error {
	fmt.Printf("Decrypting \"%s\" to \"%s\" using %s.\n", clk.inputFilePath, clk.outputFilePath, clk.cryptoAlgorithm.Name())

	// open input file
	in, err := os.Open(clk.inputFilePath)
	if err != nil {
		return fmt.Errorf("error opening input file: %w", err)
	}
	defer in.Close()

	// open output file
	out, err := os.Create(clk.outputFilePath)
	if err != nil {
		return fmt.Errorf("error creating output file: %w", err)
	}
	defer out.Close()

	// decrypt file
	if err := clk.cryptoAlgorithm.Unseal(in, out, psw); err != nil {
		return fmt.Errorf("error decrypting file: %w", err)
	}

	return nil
}

//* CLI Logic */

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

		encryptionAlgorithmName string // name of algorithm used for encryption
		encryptionReplace       bool   // whether to remove the source file after encryption

		decryptionAlgorithmName string // name of algorithm used for decryption
		decryptionReplace       bool   // whether to remove the source file after decryption
	)
	rootCommand := &cobra.Command{
		Use:   "cloak",
		Short: "Cloak allows you to encrypt and decrypt files",
		Run: func(cmd *cobra.Command, args []string) {
			// display program version and exit if flag set
			if displayVersion {
				fmt.Printf("Cloak v%s by Astrorick\n", appVersion.String())
				os.Exit(0)
			}

			// display help and exit if no args provided
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
		Long:  "Encrypt the file provided as input with the algorithm specified after the optional -x flag and write the result to the output file. If the optional -r flag is passed, the source file is then deleted.",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			// read input and output file paths from arguments
			encryptionInputFilePath := args[0]
			encryptionOutputFilePath := args[1]

			// check if input file exists
			inputExists, err := fileExists(encryptionInputFilePath)
			if err != nil {
				log.Fatal(err)
			}
			if !inputExists {
				log.Fatalf("Input file \"%s\" does not exist.\n", encryptionInputFilePath)
			}

			// check that output file does not already exist
			outputExists, err := fileExists(encryptionOutputFilePath)
			if err != nil {
				log.Fatal(err)
			}
			if outputExists && !confirmOverwrite(encryptionOutputFilePath) {
				fmt.Println("Operation cancelled by user.")
				os.Exit(0)
			}

			// check crypto algorithm
			encryptionAlgorithm, ok := implementedAlgorithms[encryptionAlgorithmName]
			if !ok {
				fmt.Printf("Unsupported encryption algorithm \"%s\". Implemented algorithms: (%s).", encryptionAlgorithmName, strings.Join(getAlgorithmNames(), ", "))
				os.Exit(1)
			}

			// generate config from args and flags
			clk.inputFilePath = encryptionInputFilePath
			clk.outputFilePath = encryptionOutputFilePath
			clk.cryptoAlgorithm = encryptionAlgorithm

			// ask user for password and encrypt
			if err := clk.Encrypt(requestUserPassword()); err != nil {
				_ = os.Remove(clk.outputFilePath)
				log.Fatal(err)
			}

			// remove original file if flag was set
			if encryptionReplace {
				if err := os.Remove(clk.inputFilePath); err != nil {
					log.Fatal(err)
				}
			}
		},
	}
	decryptCommand := &cobra.Command{
		Use:   "dec input output",
		Short: "Decrypt files",
		Long:  "Decrypt the file provided as input with the algorithm specified after the optional -x flag and write the result to the output file. If the optional -r flag is passed, the source file is then deleted.",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			// read input and output file paths from arguments
			decryptionInputFilePath := args[0]
			decryptionOutputFilePath := args[1]

			// check if input file exists
			inputExists, err := fileExists(decryptionInputFilePath)
			if err != nil {
				log.Fatal(err)
			}
			if !inputExists {
				log.Fatalf("Input file \"%s\" does not exist.\n", decryptionInputFilePath)
			}

			// check that output file does not already exist
			outputExists, err := fileExists(decryptionOutputFilePath)
			if err != nil {
				log.Fatal(err)
			}
			if outputExists && !confirmOverwrite(decryptionOutputFilePath) {
				fmt.Println("Operation cancelled by user.")
				os.Exit(0)
			}

			// check crypto algorithm
			decryptionAlgorithm, ok := implementedAlgorithms[decryptionAlgorithmName]
			if !ok {
				fmt.Printf("Unsupported decryption algorithm \"%s\". Implemented algorithms: (%s).", decryptionAlgorithmName, strings.Join(getAlgorithmNames(), ", "))
				os.Exit(1)
			}

			// generate config from args and flags
			clk.inputFilePath = decryptionInputFilePath
			clk.outputFilePath = decryptionOutputFilePath
			clk.cryptoAlgorithm = decryptionAlgorithm

			// ask user for password and decrypt
			if err := clk.Decrypt(requestUserPassword()); err != nil {
				_ = os.Remove(clk.outputFilePath)
				log.Fatal(err)
			}

			// remove original file if flag was set
			if decryptionReplace {
				if err := os.Remove(clk.inputFilePath); err != nil {
					log.Fatal(err)
				}
			}
		},
	}
	displayAlgosCommand := &cobra.Command{
		Use:   "algos",
		Short: "Display implemented algorithms",
		Long:  "Display a list of implemented algorithms for encryption and decryption",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Implemented algorithms: (%s)\n", strings.Join(getAlgorithmNames(), ", "))
		},
	}
	displayVersionCommand := &cobra.Command{
		Use:   "version",
		Short: "Display program version",
		Long:  "Display the current version of this program",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Cloak v%s by Astrorick\n", appVersion.String())
		},
	}

	//* Register Flags and Commands */
	rootCommand.Flags().BoolVarP(&displayVersion, "version", "v", false, "Display program version")
	encryptCommand.Flags().StringVarP(&encryptionAlgorithmName, "algorithm", "x", defaultAlgorithm, fmt.Sprintf("Encryption algorithm (%s)", strings.Join(getAlgorithmNames(), ", ")))
	encryptCommand.Flags().BoolVarP(&encryptionReplace, "replace", "r", false, "Remove source file after encryption")
	decryptCommand.Flags().StringVarP(&decryptionAlgorithmName, "algorithm", "x", defaultAlgorithm, fmt.Sprintf("Decryption algorithm (%s)", strings.Join(getAlgorithmNames(), ", ")))
	decryptCommand.Flags().BoolVarP(&decryptionReplace, "replace", "r", false, "Remove source file after decryption")
	rootCommand.AddCommand(encryptCommand, decryptCommand, displayAlgosCommand, displayVersionCommand)

	//* Run Root Command */
	if err := rootCommand.Execute(); err != nil {
		log.Fatal(err)
	}
}

//* Auxiliary Functions */

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

func getAlgorithmNames() []string {
	algoNames := make([]string, 0, len(implementedAlgorithms))
	for algoName := range implementedAlgorithms {
		algoNames = append(algoNames, algoName)
	}

	slices.Sort(algoNames)

	return algoNames
}

func requestUserPassword() string {
	// define set of allowed characters in passwords
	allowedCharacters := regexp.MustCompile(`^[\x21-\x7E]+$`)

	for {
		// ask for password
		fmt.Print("Enter password: ")
		bytePassword, _ := term.ReadPassword(int(syscall.Stdin)) // using term for masked input
		fmt.Println()
		providedPassword := string(bytePassword)

		// check password length
		if len(providedPassword) < 8 {
			fmt.Println("Password too short. Minimum 8 characters.")
			continue
		}

		// check password content
		if !allowedCharacters.MatchString(providedPassword) {
			fmt.Println("Password contains invalid characters. Use only A-Z, a-z, 0-9, and standard special characters (no spaces).")
			continue
		}

		// confirm password
		fmt.Print("Confirm password: ")
		byteConfirm, _ := term.ReadPassword(int(syscall.Stdin)) // using term for masked input
		fmt.Println()
		confirmPassword := string(byteConfirm)

		// check passwords match
		if providedPassword == confirmPassword {
			return providedPassword
		}

		fmt.Println("Passwords do not match. Try again.")
	}
}
