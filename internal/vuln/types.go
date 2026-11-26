package vuln

import "time"

// Affected states that Package in Ecosystem is affected by VulnID until Fixed
// (empty Fixed = no fix released yet). Data always comes from the distribution's own
// advisories, so backported fixes are respected.
type Affected struct {
	Source         string
	Ecosystem      string
	Package        string
	VulnID         string
	Advisory       string
	Introduced     string
	Fixed          string
	DistroSeverity string
}

// Info is vulnerability metadata (CVSS etc.). Zero fields mean "unknown".
type Info struct {
	ID         string
	Summary    string
	Published  time.Time
	CVSSScore  float64
	CVSSVector string
	CVSSSource string
	Severity   string
}

// Sink receives parsed feed records.
type Sink interface {
	Affected(a Affected) error
	Info(i Info) error
}

// KEVEntry is one CISA Known Exploited Vulnerabilities record.
type KEVEntry struct {
	CVE        string
	DateAdded  string
	DueDate    string
	Ransomware string
	Name       string
}

// EPSSEntry is one FIRST EPSS score.
type EPSSEntry struct {
	CVE        string
	Score      float64
	Percentile float64
}
