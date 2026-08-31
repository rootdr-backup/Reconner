// Package version exposes Reconner's immutable build identity. The defaults are
// intentionally useful for local `go run` builds; release and Docker builds set
// all three values with -ldflags (see Makefile and Dockerfile).
package version

var (
	// Current is a semantic version without a leading "v".
	Current = "dev"
	// Commit is the source revision used for this binary.
	Commit = "unknown"
	// BuildDate is an RFC3339 UTC timestamp when available.
	BuildDate = "unknown"
)
