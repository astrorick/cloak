package upgrader

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
)

// [SelfUpgradeSupported] reports whether a release binary on this platform can replace itself.
// On Windows, a running program locks the binary file at its source.
func SelfUpgradeSupported() bool {
	return runtime.GOOS == "linux" || runtime.GOOS == "darwin"
}

// [Apply] replaces the running binary with the one in the release archive for this platform. Call it only when [SelfUpgradeSupported] reports true.
// The running binary is only touched by the final rename, so any earlier failure leaves it as it was.
func Apply(release *Release) error {
	//* Release Asset

	// find this platform's archive among the release assets
	requiredArchiveName := fmt.Sprintf("cloak-%s-%s-%s.zip", release.TagName, runtime.GOOS, runtime.GOARCH)
	var requiredArchiveURL string
	for _, asset := range release.Assets {
		if asset.Name == requiredArchiveName {
			requiredArchiveURL = asset.BrowserDownloadURL
		}
	}
	if requiredArchiveURL == "" {
		return fmt.Errorf("release %s has no archive for %s/%s", release.TagName, runtime.GOOS, runtime.GOARCH)
	}

	//* Download and Extraction

	// download the archive into memory
	response, err := http.Get(requiredArchiveURL)
	if err != nil {
		return fmt.Errorf("error downloading %s: %w", requiredArchiveName, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download request for %s returned status code %s", requiredArchiveName, response.Status)
	}
	archive, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("error downloading %s: %w", requiredArchiveName, err)
	}

	// open the archive in memory and the binary inside it
	zipReader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return fmt.Errorf("error opening %s: %w", requiredArchiveName, err)
	}
	binary, err := zipReader.Open("cloak")
	if err != nil {
		return fmt.Errorf("error finding the binary in %s: %w", requiredArchiveName, err)
	}
	defer binary.Close()

	//* Replacement

	// locate the running binary, following symlinks so that the real file is replaced instead of the eventual link pointing to it
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("error locating the running binary: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("error locating the running binary: %w", err)
	}
	exeInfo, err := os.Stat(exePath)
	if err != nil {
		return fmt.Errorf("error reading the running binary: %w", err)
	}

	// write the new binary to a temporary file in the same directory, since a rename cannot move a file across filesystems
	tempFile, err := os.CreateTemp(filepath.Dir(exePath), ".cloak-upgrade-*")
	if err != nil {
		return fmt.Errorf("error creating the new binary: %w", err)
	}
	defer os.Remove(tempFile.Name()) // security measure, only triggers if anything goes wrong before the rename so no leftover binary remains
	if _, err := io.Copy(tempFile, binary); err != nil {
		tempFile.Close()
		return fmt.Errorf("error writing the new binary: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("error writing the new binary: %w", err)
	}

	// give it the same permissions of the running binary
	if err := os.Chmod(tempFile.Name(), exeInfo.Mode().Perm()); err != nil {
		return fmt.Errorf("error setting permissions on the new binary: %w", err)
	}

	// rename the binary atomically so that it points the binary's path to the new file, while the running process keeps using the old one until it exits
	if err := os.Rename(tempFile.Name(), exePath); err != nil {
		return fmt.Errorf("error replacing the running binary: %w", err)
	}

	return nil
}
