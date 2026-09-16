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
	fmt.Printf("Cloak v%s by Astrorick\n", appVersion.String())
}

// FileExists reports whether filePath exists and returns its [os.FileInfo], which is nil when filePath does not exist. It returns an error if filePath cannot be accessed or is a directory.
func FileExists(filePath string) (bool, os.FileInfo, error) {
	fileInfo, err := os.Stat(filePath)

	// no error
	if err == nil {
		// reject directories with the same error the os package reports for them
		if fileInfo.IsDir() {
			return false, nil, &os.PathError{Op: "stat", Path: filePath, Err: syscall.EISDIR}
		}

		return true, fileInfo, nil
	}

	// file does not exist
	if errors.Is(err, os.ErrNotExist) {
		return false, nil, nil
	}

	// other errors
	return false, nil, err
}

// ConfirmOverwrite asks the user whether to overwrite filePath, repeating until a valid answer is provided. An empty answer counts as no.
func ConfirmOverwrite(filePath string) bool {
	affirmativeAnswers := []string{"y", "yes"}
	negativeAnswers := []string{"n", "no", ""}
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("Output file \"%s\" already exists. Overwrite? (y/N): ", filePath)

	// keep asking the user until they provides an acceptable answer
	for {
		userInput, _ := reader.ReadString('\n')
		userAnswer := strings.ToLower(strings.TrimSpace(userInput))

		// check if answer is negative
		if slices.Contains(negativeAnswers, userAnswer) {
			return false
		}

		// check if answer is positive
		if slices.Contains(affirmativeAnswers, userAnswer) {
			return true
		}

		// repeat question
		fmt.Printf("Invalid answer. Overwrite output file \"%s\"? (y/N): ", filePath)
	}
}

// RequestUserPassword prompts for a password with masked input, repeating until it passes the [pswgen.ValidatePassword] check. If confirm is true, the password must also be entered a second time. It returns an error if the password cannot be read, e.g. when stdin is not a terminal.
func RequestUserPassword(confirm bool) (string, error) {
	for {
		// ask for password
		fmt.Print("Enter password: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin)) // using term package for masked input
		fmt.Println()
		if err != nil {
			return "", err
		}
		providedPassword := string(bytePassword)

		// validate password
		if !pswgen.ValidatePassword(providedPassword) {
			fmt.Printf("Invalid password. Use at least %d characters, only A-Z, a-z, 0-9, and the symbols %s (no spaces).\n", pswgen.MinPasswordLength, pswgen.AllowedSymbols)
			continue
		}

		// skip confirmation if not required
		if !confirm {
			return providedPassword, nil
		}

		// ask for password again
		fmt.Print("Confirm password: ")
		byteConfirm, err := term.ReadPassword(int(syscall.Stdin)) // using term package for masked input
		fmt.Println()
		if err != nil {
			return "", err
		}
		confirmPassword := string(byteConfirm)

		// check if passwords match
		if providedPassword == confirmPassword {
			return providedPassword, nil
		} else {
			fmt.Println("Passwords do not match. Try again.")
			continue
		}
	}
}
