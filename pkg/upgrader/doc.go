// Package upgrader backs the "cloak upgrade" command.
//
// Cloak is distributed through two channels, and each binary looks for new versions in the channel it was installed from:
//   - Release binaries, downloaded from GitHub releases, ask the GitHub API for the latest release. On Linux and macOS they can automatically replace themselves with it.
//   - Binaries built with "go install" ask the Go command for the latest module version, which honors the user's own proxy settings. Upgrading them means running "go install" manually.
//
// Nothing in this package runs unless the user explicitly asks for an upgrade.
package upgrader
