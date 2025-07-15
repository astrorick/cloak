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

type CryptoAlgorithm interface {
	Name() string
	Description() string
	Encrypt(input io.Reader, output io.Writer, psw string) error
	Decrypt(input io.Reader, output io.Writer, psw string) error
}

var implementedAlgorithms = map[string]CryptoAlgorithm{
	//* Advanced Encryption Standard (AES) Family */
	"aes128": algos.NewAESGCM128(),
	"aes192": algos.NewAESGCM192(),
	"aes256": algos.NewAESGCM256(),

	//* Blowfish Family */
	// TODO "blowfish": algos.NewBlowfish(),

	//* ChaCha20 Family */
	// TODO "chacha20": algos.NewChaCha20(),
	"chacha20poly1305": algos.NewChaCha20Poly1305(),

	//* Ascon Family */
	// TODO: "ascon": algos.NewAscon(),
}
var defaultAlgorithm = implementedAlgorithms["aes256"]

//* CLI Logic */

func main() {
	//* Program Version */
	appVersion := &semantika.Version{
		Major: 0,
		Minor: 3,
		Patch: 0,
	}

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
			inputFileExists, err := fileExists(inputFilePath)
			if err != nil {
				log.Fatal(err)
			}
			if !inputFileExists {
				log.Fatalf("Input file \"%s\" does not exist.\n", inputFilePath)
			}

			// check that output file does not already exist
			outputFileExists, err := fileExists(outputFilePath)
			if err != nil {
				log.Fatal(err)
			}
			if outputFileExists && !confirmOverwrite(outputFilePath) {
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
			if err := algo.Encrypt(in, out, requestUserPassword()); err != nil {
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
			inputFileExists, err := fileExists(inputFilePath)
			if err != nil {
				log.Fatal(err)
			}
			if !inputFileExists {
				log.Fatalf("Input file \"%s\" does not exist.\n", inputFilePath)
			}

			// check that output file does not already exist
			outputFileExists, err := fileExists(outputFilePath)
			if err != nil {
				log.Fatal(err)
			}
			if outputFileExists && !confirmOverwrite(outputFilePath) {
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
			if err := algo.Decrypt(in, out, requestUserPassword()); err != nil {
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
	encryptCommand.Flags().BoolVarP(&encryptionReplace, "replace", "r", false, "remove source file after encryption")
	decryptCommand.Flags().StringVarP(&decryptionAlgorithmName, "algorithm", "x", defaultAlgorithm.Name(), fmt.Sprintf("decryption algorithm (%s)", strings.Join(getAlgorithmNames(), ", ")))
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

// fileExists returns (true, nil) if the file specified by filePath exists, (false, nil) if it doesn't, or (false, err) if there were problems accessing the file.
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

// confirmOverwrite asks the user if they want to overwrite the file specified by filePath until they provide an acceptable answer. It returns true if the file should be overwritten, and false otherwise.
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

// requestUserPassword allows the user to input a password while following security guidelines (minimum length, allowed characters, etc.).
func requestUserPassword() string {
	// define set of allowed characters in passwords
	allowedCharacters := regexp.MustCompile(`^[\x21-\x7E]+$`)

	for {
		// ask for password
		fmt.Print("Enter password: ")
		bytePassword, _ := term.ReadPassword(int(syscall.Stdin)) // using term package for masked input
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

		// check if passwords match
		if providedPassword == confirmPassword {
			return providedPassword
		}

		fmt.Println("Passwords do not match. Try again.")
	}
}
