package vuln

import (
	"fmt"
	"math"
	"strings"
)

// RiskInput holds everything the risk score considers for one finding.
type RiskInput struct {
	CVSS         float64
	Severity     string // from CVSS or distro (critical|high|medium|low|unknown)
	DistroSev    string // raw distro urgency, e.g. "unimportant"
	EPSS         float64
	EPSSPct      float64
	KEV          bool
	FixAvailable bool
	Exposed      bool
}

// RiskComponent is one explained contribution to the score. Detail is the English
// explanation; Msgs carries the same explanation as message-catalog keys (risk.*)
// with preformatted string arguments so the UI can render it in any language.
type RiskComponent struct {
	Name   string    `json:"name"`
	Points float64   `json:"points"`
	Detail string    `json:"detail"`
	Msgs   []RiskMsg `json:"msgs,omitempty"`
}

// RiskMsg is a translatable message: catalog key plus string arguments. An argument
// of the form "severity.<level>" is itself a catalog key.
type RiskMsg struct {
	Key  string   `json:"key"`
	Args []string `json:"args,omitempty"`
}

var severityPoints = map[string]float64{"critical": 57, "high": 45, "medium": 30, "low": 12, "unknown": 24}

// Score computes a 0–100 risk score and its components:
//
//	severity   CVSS × 6 (max 60), or a severity-derived default when CVSS is unknown;
//	           halved when the distribution rates the issue unimportant/negligible/low
//	EPSS       percentile × 15
//	KEV        +15 if listed in CISA KEV
//	exposure   +10 if the package's service listens on a non-loopback address
//	no fix     total × 0.85 when no fixed package is available (less actionable)
func Score(in RiskInput) (float64, []RiskComponent) {
	var comps []RiskComponent
	sev := in.Severity
	if sev == "" {
		sev = "unknown"
	}
	var pts float64
	var detail string
	var msgs []RiskMsg
	if in.CVSS > 0 {
		pts = in.CVSS * 6
		cvss := fmt.Sprintf("%.1f", in.CVSS)
		detail = fmt.Sprintf("CVSS %s (%s)", cvss, sev)
		msgs = append(msgs, RiskMsg{"risk.cvss", []string{cvss, "severity." + sev}})
	} else {
		pts = severityPoints[sev]
		detail = "severity " + sev + " (no CVSS score)"
		msgs = append(msgs, RiskMsg{"risk.noCvss", []string{"severity." + sev}})
	}
	if ds := strings.ToLower(in.DistroSev); ds == "unimportant" || ds == "negligible" || ds == "low" || ds == "low*" {
		pts /= 2
		detail += "; distro rates it " + ds
		msgs = append(msgs, RiskMsg{"risk.distroLow", []string{ds}})
	}
	comps = append(comps, RiskComponent{"severity", round1(pts), detail, msgs})
	if in.EPSSPct > 0 {
		e, p := fmt.Sprintf("%.2f", in.EPSS*100), fmt.Sprintf("%.0f", in.EPSSPct*100)
		comps = append(comps, RiskComponent{"epss", round1(in.EPSSPct * 15), fmt.Sprintf("EPSS %s%% (percentile %s)", e, p),
			[]RiskMsg{{"risk.epss", []string{e, p}}}})
	}
	if in.KEV {
		comps = append(comps, RiskComponent{"kev", 15, "listed in CISA Known Exploited Vulnerabilities", []RiskMsg{{Key: "risk.kev"}}})
	}
	if in.Exposed {
		comps = append(comps, RiskComponent{"exposure", 10, "service is network-exposed", []RiskMsg{{Key: "risk.exposed"}}})
	}
	total := 0.0
	for _, c := range comps {
		total += c.Points
	}
	if !in.FixAvailable {
		penalty := total * 0.15
		comps = append(comps, RiskComponent{"no_fix", -round1(penalty), "no fixed package available yet", []RiskMsg{{Key: "risk.noFix"}}})
		total -= penalty
	}
	return round1(math.Max(0, math.Min(100, total))), comps
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }
