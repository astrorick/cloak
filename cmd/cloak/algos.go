package main

import (
	"fmt"

	"github.com/astrorick/cloak/pkg/algos"
	"github.com/spf13/cobra"
)

// newAlgosCommand returns the "algos" command, which lists the implemented crypto algorithms.
func newAlgosCommand() *cobra.Command {
	//* Display Algos Command */
	return &cobra.Command{
		Use:   "algos",
		Short: "List crypto algorithms",
		Long:  "Display the list of available cryptographic algorithms for encryption and decryption.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Implemented crypto algorithms for encryption/decryption:")

			for _, algoName := range algos.GetImplementedAlgoNames() {
				algo := algos.ImplementedAlgos[algoName]
				defaultMarker := ""
				if algoName == algos.DefaultAlgo.Name() {
					defaultMarker = " (default)"
				}

				fmt.Printf(" - %s: %s%s\n", algoName, algo.Description(), defaultMarker)
			}

			return nil
		},
	}
}
