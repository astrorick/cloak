package main

import (
	"errors"
	"fmt"

	"github.com/astrorick/cloak/pkg/upgrader"
	"github.com/spf13/cobra"
)

// [newUpgradeCommand] returns the "upgrade" command, which looks for a newer release on the channel the binary was installed from.
// Release binaries replace themselves with it on Linux and macOS, and point to its download page elsewhere. Go-installed binaries are shown the "go install" command to run.
func newUpgradeCommand(appVersion string, goInstalled bool) *cobra.Command {
	//* Upgrade Command */
	return &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade to the latest release",
		Long:  "Check for a newer release and upgrade to it. On Linux and macOS, release binaries replace themselves with the latest GitHub release, while on other platforms the command shows where to download it. Binaries installed with \"go install\" show the command to run instead.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			//* Current Version

			// only clean release builds can be upgraded, since development builds have no release version to compare
			currentVersion, ok := upgrader.ParseVersion(appVersion)
			if !ok {
				return fmt.Errorf("development build %s cannot be upgraded, install a stable release instead", appVersion)
			}

			//* Latest Version

			// ask the channel the binary was installed from
			var latestTag string
			var release *upgrader.Release
			var err error
			if goInstalled {
				latestTag, err = upgrader.LatestModuleVersion()
			} else if release, err = upgrader.LatestRelease(); err == nil {
				latestTag = release.TagName
			}
			if err != nil {
				return fmt.Errorf("error checking for a newer release: %w", err)
			}

			// a latest version that is not a clean release is an error, not a sign of being up to date
			latestVersion, ok := upgrader.ParseVersion(latestTag)
			if !ok {
				return errors.New("error checking for a newer release: the latest version found is not a release (" + latestTag + ")")
			}
			if !latestVersion.NewerThan(currentVersion) {
				fmt.Printf("Cloak %s is already up to date.\n", appVersion)
				return nil
			}

			//* Upgrade

			// binaries that cannot upgrade themselves exit with an error that tells the user how to upgrade manually
			if goInstalled {
				return fmt.Errorf("Cloak %s is available, upgrade by running \"go install github.com/astrorick/cloak/cmd/cloak@%s\"", latestTag, latestTag)
			}
			if !upgrader.SelfUpgradeSupported() {
				return fmt.Errorf("Cloak %s is available but cannot be installed automatically on this platform. Download it from https://github.com/astrorick/cloak/releases/tag/%s", latestTag, latestTag)
			}

			// release binaries on Linux and macOS replace themselves
			fmt.Printf("Upgrading Cloak %s to %s...\n", appVersion, latestTag)
			if err := upgrader.Apply(release); err != nil {
				return err
			}
			fmt.Printf("Cloak upgraded to %s.\n", latestTag)

			return nil
		},
	}
}
