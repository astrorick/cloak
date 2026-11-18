package upgrader

import (
	"regexp"
	"strings"

	"github.com/astrorick/semantika"
)

// [versionPattern] only matches plain release versions such as "vX.Y.Z" and nothing else.
var versionPattern = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// [ParseVersion] tries to parse the argument as a clean release version and reports the result.
// For dirty versions (e.g., "vX.Y.Z+dirty"), pseudo-versions (e.g., "vX.Y.Z-0.<timestamp>-<hash>"), dev builds (e.g., "(unversioned)") and prereleases ("vX.Y.Z-rc1"), it returns (nil, false).
func ParseVersion(v string) (*semantika.Version, bool) {
	// check the shape explicitly instead of relying on semantika rejecting anything else
	if !versionPattern.MatchString(v) {
		return nil, false
	}

	// parse into semantika
	version, err := semantika.New(strings.TrimPrefix(v, "v"))
	if err != nil {
		return nil, false
	}

	return version, true
}
