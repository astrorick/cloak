package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// [versionLine] returns the line that identifies the program and its version. The version string is used as is with no additional checks.
func versionLine(appVersion string) string {
	return fmt.Sprintf("Cloak %s by Astrorick", appVersion)
}

// [newVersionCommand] returns the "version" command, which displays the program version.
func newVersionCommand(appVersion string) *cobra.Command {
	//* Display Version Command */
	return &cobra.Command{
		Use:   "version",
		Short: "Display program version",
		Long:  "Display the current version of this program.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), versionLine(appVersion))
			return err
		},
	}
}
