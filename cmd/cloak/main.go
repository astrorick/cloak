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

	"github.com/astrorick/semantika"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

//* Cloak Logic */

type Cloak struct {
	inputFilePath  string // path to input file
	outputFilePath string // path to output file

	cryptoAlgorithm string // string representation of the crypto algorithm to use
	replaceMode     bool   // whether to remove the source file after ancryption/decryption
}

type CryptoAlgorithm interface {
	Encrypt(input io.Reader, output io.Writer, key []byte) error
	Decrypt(input io.Reader, output io.Writer, key []byte) error
}

// Encrypt encodes the input file with the specified algorithm and writes the result to the output file.
func (clk *Cloak) Encrypt(psw string) error {

	fmt.Printf("Encrypting \"%s\" to \"%s\" using %s. ", clk.inputFilePath, clk.outputFilePath, clk.cryptoAlgorithm)
	if clk.replaceMode {
		fmt.Println("The original file is deleted.")
	} else {
		fmt.Println("The original file is kept.")
	}

	return nil
}

// Decrypt decodes the input file with the specified algorithm and writes the result to the output file.
func (clk *Cloak) Decrypt(psw string) error {

	fmt.Printf("Decrypting \"%s\" to \"%s\" using %s. ", clk.inputFilePath, clk.outputFilePath, clk.cryptoAlgorithm)
	if clk.replaceMode {
		fmt.Println("The original file is deleted.")
	} else {
		fmt.Println("The original file is kept.")
	}

	return nil
}

/*func deriveKey(password string, salt string, keyLenght int) ([]byte, error) {
	salt := []byte("fixedSaltForNow") // Ideally random + stored with ciphertext
	return pbkdf2.Key()([]byte(password), salt, 100_000, keyLenght, sha256.New)
}*/

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

		encryptionAlgorithm string // algorithm used for encryption
		decryptionAlgorithm string // algorithm used for decryption
		encryptionReplace   bool   // whether to remove the source file after encryption
		decryptionReplace   bool   // whether to remove the source file after decryption

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
		Long:  "Encrypt the file provided as input with the algorithm specified after the optional -x flag (defaults to aes256). Write the result to the output file. If the optional -r flag is passed, the source file is then deleted.",
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

			// ask user for password and encrypt
			if err := clk.Encrypt(requestUserPassword()); err != nil {
				log.Fatal(err)
			}
		},
	}
	decryptCommand := &cobra.Command{ // cloak dec
		Use:   "dec input output [-x algorithm] [-r]",
		Short: "Decrypt files",
		Long:  "Decrypt the file provided as input with the algorithm specified after the optional -x flag (defaults to aes256). Write the result to the output file. If the optional -r flag is passed, the source file is then deleted.",
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

			// ask user for password and decrypt
			if err := clk.Decrypt(requestUserPassword()); err != nil {
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
	displayVersionCommand := &cobra.Command{ // cloak version
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
	encryptCommand.Flags().BoolVarP(&encryptionReplace, "replace", "r", false, "Remove source file after encryption")
	decryptCommand.Flags().StringVarP(&decryptionAlgorithm, "algorithm", "x", "aes256", fmt.Sprintf("Decryption algorithm (%s)", strings.Join(implementedAlgorithms, ", ")))
	decryptCommand.Flags().BoolVarP(&decryptionReplace, "replace", "r", false, "Remove source file after decryption")
	rootCommand.AddCommand(encryptCommand, decryptCommand, displayAlgosCommand, displayVersionCommand)

	// run root command
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

func requestUserPassword() string {
	// define set of allowed characters in passwords
	allowedCharacters := regexp.MustCompile(`^[\x21-\x7E]+$`)

	for {
		// ask for password
		fmt.Print("Enter password: ")
		bytePassword, _ := term.ReadPassword(int(syscall.Stdin)) // using term for masked input
		fmt.Println()
		providedPassword := string(bytePassword)

		// check password lenght
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
