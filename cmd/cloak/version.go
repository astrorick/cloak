package main

import (
	"github.com/astrorick/cloak/pkg/utils"
	"github.com/spf13/cobra"
)

// newVersionCommand returns the "version" command, which displays the program version.
func newVersionCommand(appVersion string) *cobra.Command {
	//* Display Version Command */
	return &cobra.Command{
		Use:   "version",
		Short: "Display program version",
		Long:  "Display the current version of this program.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			utils.PrintVersion(appVersion)
			return nil
		},
	}
}
