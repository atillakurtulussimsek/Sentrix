package vuln

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type debianRelease struct {
	Status       string `json:"status"`
	FixedVersion string `json:"fixed_version"`
	Urgency      string `json:"urgency"`
}

type debianCVE struct {
	Description string                   `json:"description"`
	Releases    map[string]debianRelease `json:"releases"`
}

// ParseDebianTracker stream-parses the Debian Security Tracker JSON
// (https://security-tracker.debian.org/tracker/data/json). Only releases whose major
// version is in wanted (e.g. {"12": true}) are emitted; nil means all known releases.
//
// Status "resolved" with fixed_version "0" means the release was never affected and is
// skipped. "open"/"undetermined" become unfixed records (Fixed = "").
func ParseDebianTracker(r io.Reader, wanted map[string]bool, sink Sink) (int, error) {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return 0, fmt.Errorf("debian tracker: %w", err)
	}
	if tok != json.Delim('{') {
		return 0, fmt.Errorf("debian tracker: expected object, got %v", tok)
	}
	n := 0
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return n, err
		}
		pkg, _ := tok.(string)
		var cves map[string]debianCVE
		if err := dec.Decode(&cves); err != nil {
			return n, fmt.Errorf("debian tracker package %s: %w", pkg, err)
		}
		for id, c := range cves {
			if !strings.HasPrefix(id, "CVE-") {
				continue
			}
			emitted := false
			for codename, rel := range c.Releases {
				major, ok := DebianCodenames[codename]
				if !ok || (wanted != nil && !wanted[major]) {
					continue
				}
				a := Affected{Source: "debian-tracker", Ecosystem: "debian:" + major, Package: pkg, VulnID: id, DistroSeverity: rel.Urgency}
				switch rel.Status {
				case "resolved":
					if rel.FixedVersion == "" || rel.FixedVersion == "0" {
						continue
					}
					a.Fixed = rel.FixedVersion
				case "open", "undetermined":
				default:
					continue
				}
				if err := sink.Affected(a); err != nil {
					return n, err
				}
				n++
				emitted = true
			}
			if emitted && c.Description != "" {
				if err := sink.Info(Info{ID: id, Summary: c.Description}); err != nil {
					return n, err
				}
			}
		}
	}
	return n, nil
}
