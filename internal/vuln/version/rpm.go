package version

import (
	"strconv"
	"strings"
)

// EVR is a parsed RPM epoch:version-release.
type EVR struct {
	Epoch   int
	Version string
	Release string
}

// ParseEVR parses "[epoch:]version[-release]". A trailing ".arch" is not stripped.
func ParseEVR(s string) EVR {
	s = strings.TrimSpace(s)
	var e EVR
	if i := strings.IndexByte(s, ':'); i >= 0 {
		e.Epoch, _ = strconv.Atoi(s[:i])
		s = s[i+1:]
	}
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		e.Version, e.Release = s[:i], s[i+1:]
	} else {
		e.Version = s
	}
	return e
}

// CompareRPM compares two EVR strings like rpm's rpmVersionCompare. A missing
// release on either side is treated as matching any release.
func CompareRPM(a, b string) int {
	ea, eb := ParseEVR(a), ParseEVR(b)
	if ea.Epoch != eb.Epoch {
		return sign(ea.Epoch - eb.Epoch)
	}
	if c := RPMVerCmp(ea.Version, eb.Version); c != 0 {
		return c
	}
	if ea.Release == "" || eb.Release == "" {
		return 0
	}
	return RPMVerCmp(ea.Release, eb.Release)
}

func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

// RPMVerCmp is a faithful port of rpm's rpmvercmp(), including '~' (pre-release)
// and '^' (post-release snapshot) handling.
func RPMVerCmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		// tilde sorts before everything
		if (i < len(a) && a[i] == '~') || (j < len(b) && b[j] == '~') {
			if i >= len(a) || a[i] != '~' {
				return 1
			}
			if j >= len(b) || b[j] != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		// caret sorts after end of string but before anything else
		if (i < len(a) && a[i] == '^') || (j < len(b) && b[j] == '^') {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if a[i] != '^' {
				return 1
			}
			if b[j] != '^' {
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		si, sj := i, j
		isNum := isDigit(a[i])
		if isNum {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}
		segA, segB := a[si:i], b[sj:j]
		if segA == "" {
			return -1 // cannot happen
		}
		if segB == "" {
			if isNum {
				return 1
			}
			return -1
		}
		if isNum {
			segA = strings.TrimLeft(segA, "0")
			segB = strings.TrimLeft(segB, "0")
			if len(segA) != len(segB) {
				return sign(len(segA) - len(segB))
			}
		}
		if c := strings.Compare(segA, segB); c != 0 {
			return c
		}
	}
	if i >= len(a) && j >= len(b) {
		return 0
	}
	if i >= len(a) {
		return -1
	}
	return 1
}
