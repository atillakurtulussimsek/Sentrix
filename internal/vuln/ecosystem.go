// Package vuln is Sentrix's vulnerability engine: distro-aware feed parsing,
// local matching of host inventories against advisories, and risk scoring.
//
// No host data ever leaves the server: feeds are downloaded and matching is local.
package vuln

import (
	"strings"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/vuln/version"
)

// DebianCodenames maps Debian release codenames to major versions.
var DebianCodenames = map[string]string{
	"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14",
}

// Ecosystem returns Sentrix's ecosystem key (e.g. "debian:12", "ubuntu:24.04",
// "alpine:3.19", "rocky:9") and version scheme for a host OS. ok is false when the
// distribution has no vulnerability data source.
func Ecosystem(o protocol.OSInfo) (key string, scheme version.Scheme, ok bool) {
	v := o.VersionID
	switch o.ID {
	case "debian":
		major := strings.SplitN(v, ".", 2)[0]
		if major == "" {
			// testing/sid have no VERSION_ID; use codename
			for c, n := range DebianCodenames {
				if c == o.Codename {
					major = n
				}
			}
		}
		return "debian:" + major, version.Dpkg, major != ""
	case "ubuntu":
		return "ubuntu:" + v, version.Dpkg, v != ""
	case "alpine":
		p := strings.Split(v, ".")
		if len(p) < 2 {
			return "", "", false
		}
		return "alpine:" + p[0] + "." + p[1], version.APK, true
	case "rocky", "almalinux":
		major := strings.SplitN(v, ".", 2)[0]
		return o.ID + ":" + major, version.RPM, major != ""
	}
	return "", "", false
}

// EcosystemScheme returns the version scheme for an ecosystem key.
func EcosystemScheme(eco string) version.Scheme {
	switch strings.SplitN(eco, ":", 2)[0] {
	case "debian", "ubuntu":
		return version.Dpkg
	case "alpine":
		return version.APK
	}
	return version.RPM
}

// NormalizeOSVEcosystem converts an OSV ecosystem string to a Sentrix key.
// Examples: "Debian:12" → "debian:12", "Ubuntu:24.04:LTS" → "ubuntu:24.04",
// "Alpine:v3.19" → "alpine:3.19", "Rocky Linux:9" → "rocky:9", "AlmaLinux:9" → "almalinux:9".
// Ubuntu Pro / FIPS streams are ignored (ok=false).
func NormalizeOSVEcosystem(e string) (string, bool) {
	parts := strings.Split(e, ":")
	if len(parts) < 2 {
		return "", false
	}
	switch parts[0] {
	case "Debian":
		return "debian:" + parts[1], true
	case "Ubuntu":
		if parts[1] == "Pro" || strings.Contains(e, "FIPS") {
			return "", false
		}
		return "ubuntu:" + parts[1], true
	case "Alpine":
		return "alpine:" + strings.TrimPrefix(parts[1], "v"), true
	case "Rocky Linux":
		return "rocky:" + parts[1], true
	case "AlmaLinux":
		return "almalinux:" + parts[1], true
	}
	return "", false
}

// OSVEcosystemFiles maps a distro ID to the OSV bucket directory that contains its data.
var OSVEcosystemFiles = map[string]string{
	"ubuntu":    "Ubuntu",
	"alpine":    "Alpine",
	"rocky":     "Rocky Linux",
	"almalinux": "AlmaLinux",
	"debian":    "Debian",
}

// Scheme aliases re-exported for callers that only import vuln.
type Scheme = version.Scheme

// SchemeDpkg etc. are the supported version schemes.
const (
	SchemeDpkg = version.Dpkg
	SchemeRPM  = version.RPM
	SchemeAPK  = version.APK
)

// CompareVersions compares two versions under a scheme.
func CompareVersions(s Scheme, a, b string) (int, error) { return version.Compare(s, a, b) }
