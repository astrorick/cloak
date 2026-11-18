package upgrader

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

const (
	latestReleaseURL = "https://api.github.com/repos/astrorick/cloak/releases/latest" // GitHub API endpoint for the latest CI release
	goModulePath     = "github.com/astrorick/cloak"                                   // Go module resolved by "go list" for go-installed binaries
)

// [Release] holds the fields of a GitHub release that Cloak uses. Every other field in the API response is ignored.
type Release struct {
	TagName string  `json:"tag_name"` // git tag of the release
	Assets  []Asset `json:"assets"`   // files attached to the release
}

// [Asset] is a file attached to a GitHub release.
type Asset struct {
	Name               string `json:"name"`                 // file name (e.g., "cloak-vX.Y.Z-linux-amd64.zip")
	BrowserDownloadURL string `json:"browser_download_url"` // direct download URL for the asset
}

//* Release Channel (GitHub) */

// [LatestRelease] returns the release that GitHub reports as latest (which corresponds to the latest release in chronological order).
// Any response other than HTTP 200 OK is treated as an error, including 404 when the repository has no releases and 403/429 when the limit for unauthenticated requests (60 per hour per IP) is used up.
func LatestRelease() (*Release, error) {
	// send the request and check release status
	response, err := http.Get(latestReleaseURL)
	if err != nil {
		return nil, fmt.Errorf("error contacting GitHub: %w", err)
	}
	defer response.Body.Close()

	// verify response status code
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub returned %s for the latest release request", response.Status)
	}

	// decode the JSON body
	var release Release
	if err := json.NewDecoder(response.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("error decoding the latest release metadata: %w", err)
	}

	return &release, nil
}

//* Go Channel (go list) */

// [LatestModuleVersion] asks the Go command which version "go install github.com/astrorick/cloak/cmd/cloak@latest" would install right now.
// The Go command applies the user's own GOPROXY, GOPRIVATE/GONOPROXY, credentials and the module's retractions so the answer matches what their next "go install" can fetch.
func LatestModuleVersion() (string, error) {
	command := exec.Command("go", "list", "-m", "-json", goModulePath+"@latest")

	// run outside any module, so that a go.mod in the user's current directory cannot affect the lookup
	command.Dir = os.TempDir()
	command.Env = append(os.Environ(), // later entries override the user's values for the same keys
		"GOTOOLCHAIN=local", // never download a different Go toolchain just to answer this
		"GOWORK=off",        // ignore any go.work files
	)

	// run it and collect stdout
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("error running go list: %w", err)
	}

	// decode the module description, of which only the version is needed
	var module struct {
		Version string
	}
	if err := json.Unmarshal(output, &module); err != nil {
		return "", fmt.Errorf("error decoding go list output: %w", err)
	}

	return module.Version, nil
}
