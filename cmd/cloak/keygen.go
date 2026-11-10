package main

import (
	"fmt"
	"os"

	"github.com/astrorick/cloak/pkg/keygen"
	"github.com/astrorick/cloak/pkg/utils"
	"github.com/spf13/cobra"
)

// newKeygenCommand returns the "keygen" command, which writes a new random cryptographic key to the output path.
func newKeygenCommand() *cobra.Command {
	//* Keygen Command */
	return &cobra.Command{
		Use:   "keygen output",
		Short: "Generate crypto keys",
		Long:  "Generate a static cryptographic key of fixed size that can be used to encrypt and decrypt files, and save it to the specified output location.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// read args
			outputFilePath := args[0]

			// check that output file does not already exist, and NEVER OVERWRITE
			outputFileExists, _, err := utils.FileExists(outputFilePath)
			if err != nil {
				return fmt.Errorf("output path error: %w", err)
			}
			if outputFileExists {
				return fmt.Errorf("output file \"%s\" already exists, aborting", outputFilePath)
			}

			// generate random cryptographic key
			key, err := keygen.GenerateRandomKey()
			if err != nil {
				return fmt.Errorf("error generating random key: %w", err)
			}

			// open output file
			outputFile, err := os.Create(outputFilePath)
			if err != nil {
				return fmt.Errorf("error creating output file: %w", err)
			}
			defer outputFile.Close()

			// write key to output file
			if _, err := outputFile.Write(key); err != nil {
				return fmt.Errorf("error writing to output file: %w", err)
			}

			return nil
		},
	}
}
