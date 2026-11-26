package vuln

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ParseKEV parses the CISA KEV JSON catalog.
func ParseKEV(r io.Reader) ([]KEVEntry, error) {
	var doc struct {
		Vulnerabilities []struct {
			CVE        string `json:"cveID"`
			Name       string `json:"vulnerabilityName"`
			DateAdded  string `json:"dateAdded"`
			DueDate    string `json:"dueDate"`
			Ransomware string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	out := make([]KEVEntry, 0, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		out = append(out, KEVEntry{CVE: v.CVE, DateAdded: v.DateAdded, DueDate: v.DueDate, Ransomware: v.Ransomware, Name: v.Name})
	}
	return out, nil
}

// ParseEPSS parses the gzip-compressed EPSS CSV (cve,epss,percentile) and calls fn per row.
func ParseEPSS(r io.Reader, fn func(EPSSEntry) error) (int, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return 0, fmt.Errorf("epss gzip: %w", err)
	}
	defer zr.Close()
	sc := bufio.NewScanner(zr)
	n := 0
	for sc.Scan() {
		l := sc.Text()
		if strings.HasPrefix(l, "#") || strings.HasPrefix(l, "cve,") || l == "" {
			continue
		}
		f := strings.Split(l, ",")
		if len(f) < 3 || !strings.HasPrefix(f[0], "CVE-") {
			continue
		}
		s, err1 := strconv.ParseFloat(f[1], 64)
		p, err2 := strconv.ParseFloat(f[2], 64)
		if err1 != nil || err2 != nil {
			continue
		}
		if err := fn(EPSSEntry{CVE: f[0], Score: s, Percentile: p}); err != nil {
			return n, err
		}
		n++
	}
	return n, sc.Err()
}
