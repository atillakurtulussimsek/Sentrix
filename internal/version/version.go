// Package version exposes build metadata injected via -ldflags.
package version

// Set at build time with -ldflags "-X .../internal/version.Version=...".
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns a human readable version string.
func String() string { return Version + " (" + Commit + ", " + Date + ")" }
