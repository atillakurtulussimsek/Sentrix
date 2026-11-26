package version

import (
	"strconv"
	"strings"
)

// DpkgVersion is a parsed Debian version: [epoch:]upstream[-revision].
type DpkgVersion struct {
	Epoch    int
	Upstream string
	Revision string
}

// ParseDpkg splits a Debian version string. Invalid epochs are treated as 0.
func ParseDpkg(v string) DpkgVersion {
	v = strings.TrimSpace(v)
	var d DpkgVersion
	if i := strings.IndexByte(v, ':'); i >= 0 {
		d.Epoch, _ = strconv.Atoi(v[:i])
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		d.Upstream, d.Revision = v[:i], v[i+1:]
	} else {
		d.Upstream = v
	}
	return d
}

// CompareDpkg compares two Debian versions per Debian Policy §5.6.12.
func CompareDpkg(a, b string) int {
	va, vb := ParseDpkg(a), ParseDpkg(b)
	if va.Epoch != vb.Epoch {
		return sign(va.Epoch - vb.Epoch)
	}
	if c := verrevcmp(va.Upstream, vb.Upstream); c != 0 {
		return c
	}
	return verrevcmp(va.Revision, vb.Revision)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// order implements dpkg's character ordering: '~' sorts before everything,
// even the end of the string; letters before non-letters.
func order(c byte) int {
	switch {
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	case c != 0:
		return int(c) + 256
	}
	return 0
}

func verrevcmp(a, b string) int {
	i, j := 0, 0
	at := func(s string, k int) byte {
		if k < len(s) {
			return s[k]
		}
		return 0
	}
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := order(at(a, i)), order(at(b, j))
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}
