package version

import (
	"strconv"
	"strings"
)

// apk suffix ranks: pre-release suffixes sort before "no suffix", post-release after.
var apkSuffixRank = map[string]int{
	"alpha": 0, "beta": 1, "pre": 2, "rc": 3,
	"":    4,
	"cvs": 5, "svn": 6, "git": 7, "hg": 8, "p": 9,
}

type apkVersion struct {
	nums     []string
	letter   byte
	suffixes [][2]int // rank, number
	rev      int
	invalid  bool
}

func parseAPK(v string) apkVersion {
	var p apkVersion
	v = strings.TrimSpace(v)
	if i := strings.LastIndex(v, "-r"); i >= 0 {
		if n, err := strconv.Atoi(v[i+2:]); err == nil {
			p.rev = n
			v = v[:i]
		}
	}
	// strip "~hash" commit suffix (apk 2.12+)
	if i := strings.IndexByte(v, '~'); i >= 0 {
		v = v[:i]
	}
	main, rest, _ := strings.Cut(v, "_")
	// main: digits(.digits)*[letter]
	if n := len(main); n > 0 && isAlpha(main[n-1]) {
		p.letter = main[n-1]
		main = main[:n-1]
	}
	p.nums = strings.Split(main, ".")
	for _, s := range p.nums {
		if s == "" {
			p.invalid = true
		}
		for k := 0; k < len(s); k++ {
			if !isDigit(s[k]) {
				p.invalid = true
			}
		}
	}
	if rest != "" {
		for _, sfx := range strings.Split(rest, "_") {
			k := 0
			for k < len(sfx) && isAlpha(sfx[k]) {
				k++
			}
			rank, ok := apkSuffixRank[sfx[:k]]
			if !ok {
				p.invalid = true
				continue
			}
			n, _ := strconv.Atoi(sfx[k:])
			p.suffixes = append(p.suffixes, [2]int{rank, n})
		}
	}
	return p
}

func cmpNumStr(a, b string, fractional bool) int {
	if fractional && (strings.HasPrefix(a, "0") || strings.HasPrefix(b, "0")) {
		// apk compares components with a leading zero as decimal fractions (string compare)
		return strings.Compare(a, b)
	}
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return sign(len(a) - len(b))
	}
	return strings.Compare(a, b)
}

// CompareAPK compares Alpine package versions (e.g. 1.2.3_rc1-r0).
func CompareAPK(a, b string) int {
	if a == b {
		return 0
	}
	pa, pb := parseAPK(a), parseAPK(b)
	if pa.invalid || pb.invalid {
		return RPMVerCmp(a, b) // best-effort fallback for malformed versions
	}
	for k := 0; k < len(pa.nums) || k < len(pb.nums); k++ {
		if k >= len(pa.nums) {
			return -1
		}
		if k >= len(pb.nums) {
			return 1
		}
		if c := cmpNumStr(pa.nums[k], pb.nums[k], k > 0); c != 0 {
			return c
		}
	}
	if pa.letter != pb.letter {
		return sign(int(pa.letter) - int(pb.letter))
	}
	for k := 0; k < len(pa.suffixes) || k < len(pb.suffixes); k++ {
		sa, sb := [2]int{apkSuffixRank[""], 0}, [2]int{apkSuffixRank[""], 0}
		if k < len(pa.suffixes) {
			sa = pa.suffixes[k]
		}
		if k < len(pb.suffixes) {
			sb = pb.suffixes[k]
		}
		if sa[0] != sb[0] {
			return sign(sa[0] - sb[0])
		}
		if sa[1] != sb[1] {
			return sign(sa[1] - sb[1])
		}
	}
	return sign(pa.rev - pb.rev)
}
