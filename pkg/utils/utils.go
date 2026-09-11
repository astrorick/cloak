// Package utils provides shared helpers for the Cloak CLI.
package utils

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"syscall"

	"github.com/astrorick/cloak/pkg/pswgen"
	"github.com/astrorick/semantika"
	"golang.org/x/term"
)

// PrintVersion prints the app version to stdout.
func PrintVersion(appVersion *semantika.Version) {
	fmt.Printf("Cloak v%s by Astrorick.\n", appVersion.String())
}

// FileExists reports whether filePath exists. It returns an error if filePath cannot be accessed.
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

// ConfirmOverwrite asks the user whether to overwrite filePath, repeating until the answer is valid. An empty answer counts as yes.
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

// RequestUserPassword prompts for a password with masked input, repeating until it passes [ValidatePassword] and is confirmed.
func RequestUserPassword() string {
	for {
		// ask for password
		fmt.Print("Enter password: ")
		bytePassword, _ := term.ReadPassword(int(syscall.Stdin)) // using term package for masked input
		fmt.Println()
		providedPassword := string(bytePassword)

		// validate password
		if !ValidatePassword(providedPassword) {
			fmt.Printf("Invalid password. Use only A-Z, a-z, 0-9, and the symbols %s (no spaces). Minimum 8 characters.\n", pswgen.AllowedSymbols)
			continue
		}

		// ask for password again
		fmt.Print("Confirm password: ")
		byteConfirm, _ := term.ReadPassword(int(syscall.Stdin)) // using term for masked input
		fmt.Println()
		confirmPassword := string(byteConfirm)

		// check if passwords match
		if providedPassword == confirmPassword {
			return providedPassword
		} else {
			fmt.Println("Passwords do not match. Try again.")
			continue
		}
	}
}

// ValidatePassword reports whether psw is at least 8 characters long and uses only characters from [pswgen.Charset].
func ValidatePassword(psw string) bool {
	// check password length
	if len(psw) < 8 {
		return false
	}

	// check for valid password content
	for _, r := range psw {
		if !strings.ContainsRune(pswgen.Charset, r) {
			return false
		}
	}

	return true
}
