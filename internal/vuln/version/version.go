// Package version implements distro-native package version comparison:
// Debian dpkg, RPM (EVR, rpmvercmp) and Alpine apk.
//
// These comparators decide whether an installed package is fixed; they follow the
// reference algorithms exactly (dpkg lib/dpkg/version.c, rpm rpmio/rpmvercmp.c,
// apk-tools src/version.c) and are covered by table tests with known tricky cases.
package version

import "fmt"

// Scheme identifies a version comparison algorithm.
type Scheme string

// Supported schemes.
const (
	Dpkg Scheme = "dpkg"
	RPM  Scheme = "rpm"
	APK  Scheme = "apk"
)

// Compare returns -1, 0 or 1 comparing a and b under scheme s.
func Compare(s Scheme, a, b string) (int, error) {
	switch s {
	case Dpkg:
		return CompareDpkg(a, b), nil
	case RPM:
		return CompareRPM(a, b), nil
	case APK:
		return CompareAPK(a, b), nil
	default:
		return 0, fmt.Errorf("unknown version scheme %q", s)
	}
}

// SchemeForDistro maps an os-release ID to its version scheme.
func SchemeForDistro(osID string) (Scheme, bool) {
	switch osID {
	case "debian", "ubuntu", "raspbian", "linuxmint", "pop":
		return Dpkg, true
	case "rocky", "almalinux", "rhel", "centos", "fedora", "ol", "amzn":
		return RPM, true
	case "alpine":
		return APK, true
	}
	return "", false
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
