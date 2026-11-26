package vuln

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// OSVRecord is the subset of the OSV schema Sentrix uses.
type OSVRecord struct {
	ID        string    `json:"id"`
	Aliases   []string  `json:"aliases"`
	Upstream  []string  `json:"upstream"`
	Summary   string    `json:"summary"`
	Details   string    `json:"details"`
	Published time.Time `json:"published"`
	Withdrawn string    `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
		EcosystemSpecific map[string]any `json:"ecosystem_specific"`
		Severity          []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
	} `json:"affected"`
}

// cveIDs returns the CVE identifiers a record is about.
func (r OSVRecord) cveIDs() []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimPrefix(s, "UBUNTU-")
		s = strings.TrimPrefix(s, "DEBIAN-")
		s = strings.TrimPrefix(s, "ALPINE-")
		if strings.HasPrefix(s, "CVE-") && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	add(r.ID)
	for _, a := range r.Upstream {
		add(a)
	}
	for _, a := range r.Aliases {
		add(a)
	}
	if len(out) == 0 {
		out = []string{r.ID}
	}
	return out
}

// EmitOSV converts one OSV record into Affected/Info records for wanted ecosystems
// (nil = all supported).
func EmitOSV(rec OSVRecord, source string, wanted map[string]bool, sink Sink) (int, error) {
	if rec.Withdrawn != "" {
		return 0, nil
	}
	n := 0
	ids := rec.cveIDs()
	advisory := ""
	if !strings.HasPrefix(rec.ID, "CVE-") {
		advisory = rec.ID
	}
	for _, af := range rec.Affected {
		eco, ok := NormalizeOSVEcosystem(af.Package.Ecosystem)
		if !ok || (wanted != nil && !wanted[eco]) {
			continue
		}
		sev := ""
		for _, s := range af.Severity {
			if s.Type == "Ubuntu" {
				sev = s.Score
			}
		}
		if u, ok := af.EcosystemSpecific["urgency"].(string); ok && sev == "" {
			sev = u
		}
		var pairs [][2]string // introduced, fixed
		for _, rg := range af.Ranges {
			if rg.Type != "ECOSYSTEM" {
				continue
			}
			intro := ""
			for _, ev := range rg.Events {
				if ev.Introduced != "" {
					intro = ev.Introduced
				}
				if ev.Fixed != "" {
					pairs = append(pairs, [2]string{intro, ev.Fixed})
					intro = ""
				}
			}
			if intro != "" {
				pairs = append(pairs, [2]string{intro, ""}) // open-ended: no fix yet
			}
		}
		for _, p := range pairs {
			intro := p[0]
			if intro == "0" {
				intro = ""
			}
			for _, id := range ids {
				if err := sink.Affected(Affected{Source: source, Ecosystem: eco, Package: af.Package.Name, VulnID: id,
					Advisory: advisory, Introduced: intro, Fixed: p[1], DistroSeverity: sev}); err != nil {
					return n, err
				}
				n++
			}
		}
	}
	if n > 0 {
		info := Info{Summary: rec.Summary, Published: rec.Published}
		if info.Summary == "" {
			info.Summary = firstLine(rec.Details)
		}
		for _, s := range rec.Severity {
			if strings.HasPrefix(s.Type, "CVSS_V3") {
				if sc, ok := CVSS3Score(s.Score); ok {
					info.CVSSScore, info.CVSSVector, info.CVSSSource = sc, s.Score, "osv"
					info.Severity = SeverityFromScore(sc)
				}
			}
		}
		for _, id := range ids {
			info.ID = id
			if err := sink.Info(info); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// ParseOSVZip reads an OSV ecosystem export (all.zip) and emits records.
func ParseOSVZip(zr *zip.Reader, source string, wanted map[string]bool, sink Sink) (int, error) {
	total := 0
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return total, err
		}
		var rec OSVRecord
		err = json.NewDecoder(io.LimitReader(rc, 16<<20)).Decode(&rec)
		rc.Close()
		if err != nil {
			return total, fmt.Errorf("osv %s: %w", f.Name, err)
		}
		n, err := EmitOSV(rec, source, wanted, sink)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// almaSuffix matches AlmaLinux rebuild suffixes such as ".alma.1".
var almaSuffix = regexp.MustCompile(`\.alma(\.\d+)*$`)

// RHELCrossSink copies AlmaLinux advisories to Rocky Linux ecosystems of the same major
// version. Both rebuild identical RHEL sources with identical NEVRs (Alma marks its few
// modified rebuilds with ".alma.N", which is stripped). This compensates for gaps in the
// Rocky OSV export. Records for Alma ecosystems not in AlmaWanted are dropped.
type RHELCrossSink struct {
	Inner      Sink
	AlmaWanted map[string]bool // e.g. {"almalinux:9": true}
	RockyMajor map[string]bool // e.g. {"9": true}
}

// Affected implements Sink.
func (s RHELCrossSink) Affected(a Affected) error {
	if s.AlmaWanted[a.Ecosystem] {
		if err := s.Inner.Affected(a); err != nil {
			return err
		}
	}
	major := strings.TrimPrefix(a.Ecosystem, "almalinux:")
	if strings.HasPrefix(a.Ecosystem, "almalinux:") && s.RockyMajor[major] {
		r := a
		r.Ecosystem = "rocky:" + major
		r.Fixed = almaSuffix.ReplaceAllString(a.Fixed, "")
		return s.Inner.Affected(r)
	}
	return nil
}

// Info implements Sink.
func (s RHELCrossSink) Info(i Info) error { return s.Inner.Info(i) }
