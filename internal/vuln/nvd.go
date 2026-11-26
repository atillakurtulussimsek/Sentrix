package vuln

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// ParseNVDCVE parses an NVD API 2.0 response for a single CVE and returns its metadata,
// preferring CVSS v3.1, then v3.0, then v4.0, then v2 base scores.
func ParseNVDCVE(r io.Reader) (Info, error) {
	type cvssData struct {
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
		BaseSeverity string  `json:"baseSeverity"`
	}
	type metric struct {
		Source       string   `json:"source"`
		Type         string   `json:"type"`
		CVSSData     cvssData `json:"cvssData"`
		BaseSeverity string   `json:"baseSeverity"`
	}
	var doc struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics map[string][]metric `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return Info{}, fmt.Errorf("nvd: %w", err)
	}
	if len(doc.Vulnerabilities) == 0 {
		return Info{}, fmt.Errorf("nvd: no vulnerability in response")
	}
	c := doc.Vulnerabilities[0].CVE
	info := Info{ID: c.ID}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			info.Summary = firstLine(d.Value)
		}
	}
	if t, err := time.Parse("2006-01-02T15:04:05.000", c.Published); err == nil {
		info.Published = t
	}
	for _, key := range []string{"cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"} {
		ms := c.Metrics[key]
		if len(ms) == 0 {
			continue
		}
		m := ms[0]
		for _, x := range ms {
			if x.Type == "Primary" {
				m = x
				break
			}
		}
		info.CVSSScore, info.CVSSVector, info.CVSSSource = m.CVSSData.BaseScore, m.CVSSData.VectorString, "nvd"
		sev := m.CVSSData.BaseSeverity
		if sev == "" {
			sev = m.BaseSeverity
		}
		info.Severity = NormalizeSeverity(sev)
		if info.Severity == "unknown" {
			info.Severity = SeverityFromScore(info.CVSSScore)
		}
		break
	}
	return info, nil
}
