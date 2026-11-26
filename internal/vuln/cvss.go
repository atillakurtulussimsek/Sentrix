package vuln

import (
	"math"
	"strings"
)

// CVSS3Score computes the CVSS v3.0/v3.1 base score from a vector string such as
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H". It returns ok=false for
// malformed or non-v3 vectors.
func CVSS3Score(vector string) (float64, bool) {
	if !strings.HasPrefix(vector, "CVSS:3.") {
		return 0, false
	}
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		k, v, ok := strings.Cut(part, ":")
		if !ok {
			return 0, false
		}
		m[k] = v
	}
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, okC := cia[m["C"]]
	i, okI := cia[m["I"]]
	a, okA := cia[m["A"]]
	scope := m["S"]
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = map[string]float64{"U": 0.62, "C": 0.68}[scope]
	case "H":
		pr = map[string]float64{"U": 0.27, "C": 0.5}[scope]
	}
	if av == 0 || ac == 0 || ui == 0 || pr == 0 || !okC || !okI || !okA || (scope != "U" && scope != "C") {
		return 0, false
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	expl := 8.22 * av * ac * pr * ui
	if impact <= 0 {
		return 0, true
	}
	var base float64
	if scope == "U" {
		base = math.Min(impact+expl, 10)
	} else {
		base = math.Min(1.08*(impact+expl), 10)
	}
	return roundUp1(base), true
}

// roundUp1 implements the CVSS v3.1 Roundup function.
func roundUp1(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}

// SeverityFromScore maps a CVSS base score to a qualitative severity.
func SeverityFromScore(s float64) string {
	switch {
	case s >= 9:
		return "critical"
	case s >= 7:
		return "high"
	case s >= 4:
		return "medium"
	case s > 0:
		return "low"
	}
	return "unknown"
}

// NormalizeSeverity maps distro/NVD severity words to critical|high|medium|low|unknown.
func NormalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high", "important":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low", "negligible", "unimportant":
		return "low"
	}
	return "unknown"
}
