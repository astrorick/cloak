package main

import (
	"fmt"

	"github.com/astrorick/cloak/pkg/keygen"
	"github.com/spf13/cobra"
)

// newMethodsCommand returns the "methods" command, which lists the implemented key derivation methods.
func newMethodsCommand() *cobra.Command {
	//* Display Methods Command */
	return &cobra.Command{
		Use:   "methods",
		Short: "List key derivation methods",
		Long:  "Display the list of available methods for key derivation.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Implemented methods for key derivation:")

			for _, methodName := range keygen.GetImplementedMethodNames() {
				method := keygen.ImplementedMethods[methodName]
				defaultMarker := ""
				if methodName == keygen.DefaultMethod.Name() {
					defaultMarker = " (default)"
				}

				fmt.Printf(" - %s: %s%s\n", methodName, method.Description(), defaultMarker)
			}

			return nil
		},
	}
}
