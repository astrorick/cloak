package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// [readBuildVersion] returns the version injected by the Go toolchain in the binary's build info.
// The returned string matches the git tag for automatic release builds (via GitHub workflow) and for local user builds (via "go install ...@vX.Y.Z").
// If the binary is not built on a clean working tree, it will be marked as "dirty" (e.g., "vX.Y.Z+dirty").
// If the binary is not built on a tagged commit, it will get a pseudo-version (e.g., "vX.Y.Z-0.<timestamp>-<hash>").
// If the binary is run with `go run` or built without git info, it will be marked as "(unversioned)".
func readBuildVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}

	return "(unversioned)"
}

// [isGoInstalled] reports whether the binary was built by "go install <module>@<version>" (or "go run <module>@<version>").
// Only those builds record a checksum of the main module in the build info, because the Go command downloaded the module to build it. Builds from a local checkout, including the release workflow's, leave it empty.
func isGoInstalled() bool {
	info, ok := debug.ReadBuildInfo()
	return ok && info.Main.Sum != ""
}

// [main] represents the entry point for the application. It runs the root command and handles any returned errors.
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// [run] is the main routine that merges all subcommands.
func run() error {
	//* Program Version and Install Channel */
	appVersion := readBuildVersion()
	goInstalled := isGoInstalled()

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
		newUpgradeCommand(appVersion, goInstalled),
	)
	return rootCommand.Execute()
}

// [newRootCommand] returns the root "cloak" command.
func newRootCommand(appVersion string) *cobra.Command {
	//* Root Command */
	rootCommand := &cobra.Command{
		Use:           "cloak",
		Short:         "Cloak allows you to encrypt and decrypt files using a cryptographic key or a password.",
		Version:       appVersion, // this makes Cobra automatically add the -v/--version flag, which prints the program version before any hook runs
		SilenceUsage:  true,
		SilenceErrors: true,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true, // this disables the "completion" command which is shown by default
		},
	}
	rootCommand.SetVersionTemplate(versionLine(appVersion) + "\n")

	return rootCommand
}
