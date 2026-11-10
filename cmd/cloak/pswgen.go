package main

import (
	"fmt"

	"github.com/astrorick/cloak/pkg/pswgen"
	"github.com/spf13/cobra"
)

// newPswgenCommand returns the "pswgen" command, which prints one or more cryptographically random passwords.
func newPswgenCommand() *cobra.Command {
	var (
		//* Pswgen Command Flags */
		pswgenLength int // length of each generated password
		pswgenNumber int // number of passwords to generate
	)

	//* Pswgen Command */
	pswgenCommand := &cobra.Command{
		Use:   "pswgen",
		Short: "Generate random passwords",
		Long:  "Generate one or more cryptographically random passwords using letters, digits, and the symbols " + pswgen.AllowedSymbols + ". Password length and number of generated passwords can be customized with the optional -l and -n flags.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// validate requested password length
			if pswgenLength < pswgen.MinPasswordLength {
				return fmt.Errorf("invalid password length (must be at least %d characters long, got %d)", pswgen.MinPasswordLength, pswgenLength)
			}

			// validate requested number of password
			if pswgenNumber < 1 {
				return fmt.Errorf("invalid number of passwords (must be at least 1, got %d)", pswgenNumber)
			}

			// generate and print passwords
			for range pswgenNumber {
				password, err := pswgen.GenerateRandomPassword(pswgenLength)
				if err != nil {
					return fmt.Errorf("error generating password: %w", err)
				}

				// print password to stdout
				fmt.Println(password)
			}

			return nil
		},
	}
	pswgenCommand.Flags().IntVarP(&pswgenLength, "length", "l", 32, "length of each generated password")
	pswgenCommand.Flags().IntVarP(&pswgenNumber, "number", "n", 1, "number of passwords to generate")

	return pswgenCommand
}
