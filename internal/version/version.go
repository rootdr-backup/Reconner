// Package version holds Reconner's build version. Bump Current on every release
// and tag the GitHub repo with the matching "v<Current>" tag so the in-app
// update checker (see api.handleUpdateCheck) can tell clients an update is out.
package version

// Current is the running Reconner version (semver, no leading "v").
const Current = "1.0.0"
