package utils

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"syscall"

	"github.com/astrorick/semantika"
	"golang.org/x/term"
)

// PrintAppVersion prints the provided app version to the terminal.
func PrintAppVersion(appVersion *semantika.Version) {
	fmt.Printf("Cloak v%s by Astrorick.\n", appVersion.String())
}

// ProcessFile processes the input file using the specified algorithm and flags, writing the result to the output file while taking care of I/O handling. The action function is also provided as an argument.
func ProcessFile(inputFilePath string, outputFilePath string, forceOverwrite bool, replaceOriginal bool, actionFunc func(io.Reader, io.Writer, string) error) error {
	// check that input file exists
	inputFileExists, err := FileExists(inputFilePath)
	if err != nil {
		return err
	}
	if !inputFileExists {
		return fmt.Errorf("input file %q does not exist", inputFilePath)
	}

	// check that output file does not already exist, eventually asking the user to overwrite it
	outputFileExists, err := FileExists(outputFilePath)
	if err != nil {
		return err
	}
	if outputFileExists && !forceOverwrite && !ConfirmOverwrite(outputFilePath) {
		return fmt.Errorf("operation cancelled by user")
	}

	// open input file
	inputFile, err := os.Open(inputFilePath)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	// open output file
	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	// process with action function
	if err := actionFunc(inputFile, outputFile, RequestUserPassword()); err != nil {
		_ = os.Remove(outputFilePath)
		return err
	}

	// remove original file if needed
	if replaceOriginal {
		if err := os.Remove(inputFilePath); err != nil {
			return err
		}
	}

	return nil
}

// FileExists returns (true, nil) if the file specified by filePath exists, (false, nil) if it doesn't, or (false, err) if there were problems accessing the file.
func FileExists(filePath string) (bool, error) {
	_, err := os.Stat(filePath)

	if err == nil {
		return true, nil
	}

	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}

	return false, err
}

// ConfirmOverwrite asks the user if they want to overwrite the file specified by filePath until they provide an acceptable answer. It returns true if the file should be overwritten, and false otherwise.
func ConfirmOverwrite(filePath string) bool {
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

// RequestUserPassword allows the user to input a password while following security guidelines (minimum length, allowed characters, etc.).
func RequestUserPassword() string {
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
