package utils

import (
	"bufio"
	"errors"
	"fmt"
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
	for {
		// ask for password
		fmt.Print("Enter password: ")
		bytePassword, _ := term.ReadPassword(int(syscall.Stdin)) // using term package for masked input
		fmt.Println()
		providedPassword := string(bytePassword)

		// validate password
		if !ValidatePassword(providedPassword) {
			fmt.Println("Invalid password. Use only A-Z, a-z, 0-9, and standard special characters (no spaces). Minimum 8 characters.")
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

// ValidatePassword evaluates the suitability of the provided password, returning true if the password is valid and false otherwise.
func ValidatePassword(psw string) bool {
	// check password length
	if len(psw) < 8 {
		return false
	}

	// check for valid password content
	if !regexp.MustCompile(`^[\x21-\x7E]+$`).MatchString(psw) {
		return false
	}

	return true
}
