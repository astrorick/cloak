package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/astrorick/cloak/pkg/utils"
	"github.com/spf13/cobra"
)

// readBuildVersion returns the version injected by the Go toolchain in the binary's build info.
// The returned string matches the git tag for automatic release builds (via GitHub workflow) and for local user builds (via "go install ...@vX.Y.Z").
// If the binary is not built on a clean working tree, it will be marked as "dirty" (e.g., "v0.8.0+dirty").
// If the binary is not built on a tagged commit, it will get a pseudo-version (e.g., "v0.8.1-0.<timestamp>-<hash>").
// If the binary is run with go run or built without git info, it will be marked as "(unversioned)".
func readBuildVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}

	return "(unversioned)"
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	//* Program Version */
	appVersion := readBuildVersion()

	//* Run Root Command */
	rootCommand := newRootCommand(appVersion)
	rootCommand.AddCommand(
		newKeygenCommand(),
		newPswgenCommand(),
		newEncryptCommand(),
		newDecryptCommand(),
		newAlgosCommand(),
		newMethodsCommand(),
		newVersionCommand(appVersion),
	)
	return rootCommand.Execute()
}

// newRootCommand returns the root "cloak" command, which displays the program version when -v is passed and the help text otherwise.
func newRootCommand(appVersion string) *cobra.Command {
	var (
		//* Root Command Flags */
		rootDisplayVersion bool // whether to display program version and exit
	)

	//* Root Command */
	rootCommand := &cobra.Command{
		Use:           "cloak",
		Short:         "Cloak allows you to encrypt and decrypt files using a cryptographic key or a password.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// if version flag is passed, display program version and exit
			if rootDisplayVersion {
				utils.PrintVersion(appVersion)
				return nil
			}

			// if no subcommand is given, display help instead
			return cmd.Help()
		},
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true, // this disables the "completion" command which is shown by default
		},
	}
	rootCommand.Flags().BoolVarP(&rootDisplayVersion, "version", "v", false, "program version")

	return rootCommand
}
