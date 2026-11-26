package store

import (
	"context"
	"strings"
	"time"
)

// activeExceptionSQL excludes findings covered by an active exception (alias f).
const activeExceptionSQL = ` NOT EXISTS (SELECT 1 FROM vuln_exceptions e WHERE e.vuln_id = f.vuln_id AND (e.host_id = '' OR e.host_id = f.host_id) AND (e.expires_at = 0 OR e.expires_at > ?))`

// VulnFilter filters the fleet vulnerability list.
type VulnFilter struct {
	Severity        string // critical|high|medium|low|unknown, or "high+" for high and critical
	KEV             bool
	Fixable         bool
	Query           string // CVE id or package substring
	HostID          string
	IncludeExcepted bool
	Limit           int
}

// VulnRow is one CVE aggregated across the fleet.
type VulnRow struct {
	VulnMeta
	EffSeverity string
	Hosts       int
	Packages    string
	MaxRisk     float64
	Fixable     bool
	Unfixed     bool
	FirstSeen   time.Time
}

// FleetVulns aggregates current findings per vulnerability.
func (d *DB) FleetVulns(ctx context.Context, f VulnFilter) ([]VulnRow, error) {
	q := `SELECT v.id, v.summary, v.published, v.cvss_score, v.cvss_vector, v.cvss_source, v.severity, v.epss, v.epss_pct, v.kev, v.kev_added, v.kev_due, v.kev_ransomware,
		MAX(f.severity), COUNT(DISTINCT f.host_id), GROUP_CONCAT(DISTINCT f.package), MAX(f.risk), MAX(f.fixed <> ''), MAX(f.fixed = ''), MIN(f.first_seen)
		FROM findings f JOIN vulns v ON v.id = f.vuln_id WHERE 1=1`
	var args []any
	if !f.IncludeExcepted {
		q += ` AND` + activeExceptionSQL
		args = append(args, d.now().Unix())
	}
	if f.HostID != "" {
		q += ` AND f.host_id = ?`
		args = append(args, f.HostID)
	}
	switch f.Severity {
	case "":
	case "high+":
		q += ` AND f.severity IN ('critical','high')`
	default:
		q += ` AND f.severity = ?`
		args = append(args, f.Severity)
	}
	if f.KEV {
		q += ` AND v.kev = 1`
	}
	if f.Fixable {
		q += ` AND f.fixed <> ''`
	}
	if f.Query != "" {
		q += ` AND (f.vuln_id LIKE ? OR f.package LIKE ? OR f.binaries LIKE ?)`
		like := "%" + strings.ToUpper(f.Query) + "%"
		plike := "%" + strings.ToLower(f.Query) + "%"
		args = append(args, like, plike, plike)
	}
	q += ` GROUP BY v.id ORDER BY MAX(f.risk) DESC, v.id DESC`
	if f.Limit > 0 {
		q += ` LIMIT ?`
		args = append(args, f.Limit)
	}
	rows, err := d.sql.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VulnRow
	for rows.Next() {
		var r VulnRow
		var pub, first int64
		var kev, fixable, unfixed int
		if err := rows.Scan(&r.ID, &r.Summary, &pub, &r.CVSSScore, &r.CVSSVector, &r.CVSSSource, &r.Severity, &r.EPSS, &r.EPSSPct, &kev, &r.KEVAdded, &r.KEVDue, &r.KEVRansomware,
			&r.EffSeverity, &r.Hosts, &r.Packages, &r.MaxRisk, &fixable, &unfixed, &first); err != nil {
			return nil, err
		}
		if pub > 0 {
			r.Published = time.Unix(pub, 0)
		}
		r.KEV, r.Fixable, r.Unfixed, r.FirstSeen = kev != 0, fixable != 0, unfixed != 0, time.Unix(first, 0)
		r.Packages = strings.ReplaceAll(r.Packages, ",", ", ")
		out = append(out, r)
	}
	return out, rows.Err()
}

// HostRisk is a per-host vulnerability summary (excepted findings excluded).
type HostRisk struct {
	Risk                     float64
	Critical, High, KEV, Fix int
	Total                    int
}

// HostRisks summarises findings per host.
func (d *DB) HostRisks(ctx context.Context) (map[string]HostRisk, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT f.host_id, MAX(f.risk), SUM(f.severity = 'critical'), SUM(f.severity = 'high'), SUM(v.kev), SUM(f.fixed <> ''), COUNT(*)
		FROM findings f JOIN vulns v ON v.id = f.vuln_id WHERE`+activeExceptionSQL+` GROUP BY f.host_id`, d.now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]HostRisk{}
	for rows.Next() {
		var id string
		var r HostRisk
		if err := rows.Scan(&id, &r.Risk, &r.Critical, &r.High, &r.KEV, &r.Fix, &r.Total); err != nil {
			return nil, err
		}
		out[id] = r
	}
	return out, rows.Err()
}

// PackageHost is one host that has a given package installed.
type PackageHost struct {
	HostID   string
	Hostname string
	Name     string
	Version  string
	Arch     string
}

// HostsWithPackage lists hosts with a binary or source package of that name.
func (d *DB) HostsWithPackage(ctx context.Context, name string) ([]PackageHost, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT p.host_id, h.hostname, p.name, p.version, p.arch FROM packages p JOIN hosts h ON h.id = p.host_id
		WHERE p.name = ? OR p.source = ? ORDER BY h.hostname, p.name`, name, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PackageHost
	for rows.Next() {
		var p PackageHost
		if err := rows.Scan(&p.HostID, &p.Hostname, &p.Name, &p.Version, &p.Arch); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SeverityCounts returns non-excepted finding counts per severity across the fleet (distinct CVEs).
func (d *DB) SeverityCounts(ctx context.Context) (map[string]int, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT f.severity, COUNT(DISTINCT f.vuln_id) FROM findings f WHERE`+activeExceptionSQL+` GROUP BY f.severity`, d.now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		out[s] = n
	}
	return out, rows.Err()
}
