package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/atillakurtulussimsek/Sentrix/internal/vuln"
)

// AffectedWriter replaces a feed's records for a set of ecosystems in one transaction.
// It implements vuln.Sink.
type AffectedWriter struct {
	tx   *sql.Tx
	ins  *sql.Stmt
	ctx  context.Context
	info map[string]vuln.Info
}

// BeginAffected starts replacing all records of source for the given ecosystems.
func (d *DB) BeginAffected(ctx context.Context, source string, ecosystems []string) (*AffectedWriter, error) {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	for _, e := range ecosystems {
		if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_affected WHERE source = ? AND ecosystem = ?`, source, e); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
	}
	ins, err := tx.PrepareContext(ctx, `INSERT INTO vuln_affected(source, ecosystem, package, vuln_id, advisory, introduced, fixed, distro_severity)
		VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(ecosystem, package, vuln_id, source, advisory) DO UPDATE SET fixed = excluded.fixed, introduced = excluded.introduced`)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return &AffectedWriter{tx: tx, ins: ins, ctx: ctx, info: map[string]vuln.Info{}}, nil
}

// Affected implements vuln.Sink.
func (w *AffectedWriter) Affected(a vuln.Affected) error {
	_, err := w.ins.ExecContext(w.ctx, a.Source, a.Ecosystem, a.Package, a.VulnID, a.Advisory, a.Introduced, a.Fixed, a.DistroSeverity)
	return err
}

// Info implements vuln.Sink (buffered; written on Commit).
func (w *AffectedWriter) Info(i vuln.Info) error {
	prev := w.info[i.ID]
	if prev.Summary == "" {
		prev.Summary = i.Summary
	}
	if prev.Published.IsZero() {
		prev.Published = i.Published
	}
	if prev.CVSSScore == 0 && i.CVSSScore > 0 {
		prev.CVSSScore, prev.CVSSVector, prev.CVSSSource, prev.Severity = i.CVSSScore, i.CVSSVector, i.CVSSSource, i.Severity
	}
	prev.ID = i.ID
	w.info[i.ID] = prev
	return nil
}

// Commit writes buffered metadata and commits.
func (w *AffectedWriter) Commit() error {
	defer w.ins.Close()
	for _, i := range w.info {
		if err := upsertInfo(w.ctx, w.tx, i, false); err != nil {
			_ = w.tx.Rollback()
			return err
		}
	}
	return w.tx.Commit()
}

// Rollback aborts the replacement.
func (w *AffectedWriter) Rollback() { _ = w.ins.Close(); _ = w.tx.Rollback() }

// upsertInfo inserts vulnerability metadata. Existing non-empty fields are kept unless
// authoritative is set (NVD).
func upsertInfo(ctx context.Context, q execQuerier, i vuln.Info, authoritative bool) error {
	var pub int64
	if !i.Published.IsZero() {
		pub = i.Published.Unix()
	}
	if _, err := q.ExecContext(ctx, `INSERT INTO vulns(id, summary, published, cvss_score, cvss_vector, cvss_source, severity) VALUES (?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`,
		i.ID, i.Summary, pub, i.CVSSScore, i.CVSSVector, i.CVSSSource, i.Severity); err != nil {
		return err
	}
	if authoritative {
		_, err := q.ExecContext(ctx, `UPDATE vulns SET summary = CASE WHEN ? <> '' THEN ? ELSE summary END, published = CASE WHEN ? > 0 THEN ? ELSE published END,
			cvss_score = CASE WHEN ? > 0 THEN ? ELSE cvss_score END, cvss_vector = CASE WHEN ? > 0 THEN ? ELSE cvss_vector END,
			cvss_source = CASE WHEN ? > 0 THEN ? ELSE cvss_source END, severity = CASE WHEN ? <> '' AND ? <> 'unknown' THEN ? ELSE severity END WHERE id = ?`,
			i.Summary, i.Summary, pub, pub, i.CVSSScore, i.CVSSScore, i.CVSSScore, i.CVSSVector, i.CVSSScore, i.CVSSSource, i.Severity, i.Severity, i.Severity, i.ID)
		return err
	}
	_, err := q.ExecContext(ctx, `UPDATE vulns SET summary = CASE WHEN summary = '' THEN ? ELSE summary END, published = CASE WHEN published = 0 THEN ? ELSE published END,
		cvss_score = CASE WHEN cvss_score = 0 THEN ? ELSE cvss_score END, cvss_vector = CASE WHEN cvss_vector = '' THEN ? ELSE cvss_vector END,
		cvss_source = CASE WHEN cvss_source = '' THEN ? ELSE cvss_source END, severity = CASE WHEN severity IN ('', 'unknown') THEN ? ELSE severity END WHERE id = ?`,
		i.Summary, pub, i.CVSSScore, i.CVSSVector, i.CVSSSource, i.Severity, i.ID)
	return err
}

// SaveNVDInfo stores authoritative NVD metadata and marks the CVE as checked.
func (d *DB) SaveNVDInfo(ctx context.Context, i vuln.Info) error {
	if err := upsertInfo(ctx, d.sql, i, true); err != nil {
		return err
	}
	_, err := d.sql.ExecContext(ctx, `UPDATE vulns SET nvd_checked = ? WHERE id = ?`, d.now().Unix(), i.ID)
	return err
}

// MarkNVDChecked records an NVD lookup without data (e.g. reserved CVE).
func (d *DB) MarkNVDChecked(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE vulns SET nvd_checked = ? WHERE id = ?`, d.now().Unix(), id)
	return err
}

// CVEsNeedingNVD returns CVEs with findings that lack a CVSS score and were not checked recently.
func (d *DB) CVEsNeedingNVD(ctx context.Context, limit int) ([]string, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT f.vuln_id FROM findings f JOIN vulns v ON v.id = f.vuln_id
		WHERE v.cvss_score = 0 AND v.nvd_checked < ? AND f.vuln_id LIKE 'CVE-%' GROUP BY f.vuln_id ORDER BY MAX(f.risk) DESC, f.vuln_id DESC LIMIT ?`, d.now().Add(-7*24*time.Hour).Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// SetKEV replaces the KEV flags.
func (d *DB) SetKEV(ctx context.Context, entries []vuln.KEVEntry) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, `UPDATE vulns SET kev = 0, kev_added = '', kev_due = '', kev_ransomware = '' WHERE kev = 1`); err != nil {
		return err
	}
	for _, e := range entries {
		if _, err := tx.ExecContext(ctx, `INSERT INTO vulns(id, summary, kev, kev_added, kev_due, kev_ransomware) VALUES (?,?,1,?,?,?)
			ON CONFLICT(id) DO UPDATE SET kev = 1, kev_added = excluded.kev_added, kev_due = excluded.kev_due, kev_ransomware = excluded.kev_ransomware,
			summary = CASE WHEN vulns.summary = '' THEN excluded.summary ELSE vulns.summary END`, e.CVE, e.Name, e.DateAdded, e.DueDate, e.Ransomware); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SetEPSS updates EPSS scores for CVEs already known to Sentrix.
func (d *DB) SetEPSS(ctx context.Context, scores map[string]vuln.EPSSEntry) (int, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT id FROM vulns WHERE id LIKE 'CVE-%'`)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, s)
	}
	rows.Close()
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	st, err := tx.PrepareContext(ctx, `UPDATE vulns SET epss = ?, epss_pct = ? WHERE id = ?`)
	if err != nil {
		return 0, err
	}
	defer st.Close()
	n := 0
	for _, id := range ids {
		e, ok := scores[id]
		if !ok {
			continue
		}
		if _, err := st.ExecContext(ctx, e.Score, e.Percentile, id); err != nil {
			return n, err
		}
		n++
	}
	return n, tx.Commit()
}

// AffectedIndex loads all advisories of an ecosystem keyed by package.
func (d *DB) AffectedIndex(ctx context.Context, ecosystem string) (vuln.AffectedIndex, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT source, package, vuln_id, advisory, introduced, fixed, distro_severity FROM vuln_affected WHERE ecosystem = ?`, ecosystem)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	idx := vuln.AffectedIndex{}
	for rows.Next() {
		a := vuln.Affected{Ecosystem: ecosystem}
		if err := rows.Scan(&a.Source, &a.Package, &a.VulnID, &a.Advisory, &a.Introduced, &a.Fixed, &a.DistroSeverity); err != nil {
			return nil, err
		}
		idx[a.Package] = append(idx[a.Package], a)
	}
	return idx, rows.Err()
}

// VulnMeta is stored vulnerability metadata.
type VulnMeta struct {
	ID            string
	Summary       string
	Published     time.Time
	CVSSScore     float64
	CVSSVector    string
	CVSSSource    string
	Severity      string
	EPSS, EPSSPct float64
	KEV           bool
	KEVAdded      string
	KEVDue        string
	KEVRansomware string
}

const vulnCols = `id, summary, published, cvss_score, cvss_vector, cvss_source, severity, epss, epss_pct, kev, kev_added, kev_due, kev_ransomware`

func scanVuln(sc interface{ Scan(...any) error }) (VulnMeta, error) {
	var v VulnMeta
	var pub int64
	var kev int
	err := sc.Scan(&v.ID, &v.Summary, &pub, &v.CVSSScore, &v.CVSSVector, &v.CVSSSource, &v.Severity, &v.EPSS, &v.EPSSPct, &kev, &v.KEVAdded, &v.KEVDue, &v.KEVRansomware)
	if pub > 0 {
		v.Published = time.Unix(pub, 0)
	}
	v.KEV = kev != 0
	return v, err
}

// GetVuln returns metadata for one vulnerability.
func (d *DB) GetVuln(ctx context.Context, id string) (VulnMeta, error) {
	v, err := scanVuln(d.sql.QueryRowContext(ctx, `SELECT `+vulnCols+` FROM vulns WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	return v, err
}

// VulnMetas loads metadata for the given IDs.
func (d *DB) VulnMetas(ctx context.Context, ids []string) (map[string]VulnMeta, error) {
	out := map[string]VulnMeta{}
	for start := 0; start < len(ids); start += 500 {
		chunk := ids[start:min(start+500, len(ids))]
		args := make([]any, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		rows, err := d.sql.QueryContext(ctx, `SELECT `+vulnCols+` FROM vulns WHERE id IN (?`+strings.Repeat(",?", len(chunk)-1)+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			v, err := scanVuln(rows)
			if err != nil {
				rows.Close()
				return nil, err
			}
			out[v.ID] = v
		}
		rows.Close()
	}
	return out, nil
}

// StoredFinding is a finding row joined with optional exception info.
type StoredFinding struct {
	HostID    string
	VulnID    string
	Package   string
	Installed string
	Fixed     string
	Advisory  string
	Binaries  []string
	Exposed   string
	Severity  string
	Risk      float64
	RiskJSON  string
	FirstSeen time.Time
	LastSeen  time.Time
}

// ReplaceFindings stores the current findings of a host. Findings that disappeared are
// recorded in findings_resolved. Returns new and resolved vuln IDs.
func (d *DB) ReplaceFindings(ctx context.Context, hostID string, fs []StoredFinding) (added, resolved []StoredFinding, err error) {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	now := d.now().Unix()
	existing := map[[2]string]StoredFinding{}
	rows, err := tx.QueryContext(ctx, `SELECT vuln_id, package, installed FROM findings WHERE host_id = ?`, hostID)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var f StoredFinding
		if err := rows.Scan(&f.VulnID, &f.Package, &f.Installed); err != nil {
			rows.Close()
			return nil, nil, err
		}
		f.HostID = hostID
		existing[[2]string{f.VulnID, f.Package}] = f
	}
	rows.Close()
	seen := map[[2]string]bool{}
	for _, f := range fs {
		k := [2]string{f.VulnID, f.Package}
		seen[k] = true
		if _, ok := existing[k]; !ok {
			added = append(added, f)
		}
		if f.Severity == "" {
			f.Severity = "unknown"
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO findings(host_id, vuln_id, package, installed, fixed, advisory, binaries, exposed, severity, risk, risk_json, first_seen, last_seen)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(host_id, vuln_id, package) DO UPDATE SET installed = excluded.installed, fixed = excluded.fixed,
			advisory = excluded.advisory, binaries = excluded.binaries, exposed = excluded.exposed, severity = excluded.severity, risk = excluded.risk,
			risk_json = excluded.risk_json, last_seen = excluded.last_seen`,
			hostID, f.VulnID, f.Package, f.Installed, f.Fixed, f.Advisory, strings.Join(f.Binaries, ","), f.Exposed, f.Severity, f.Risk, f.RiskJSON, now, now); err != nil {
			return nil, nil, err
		}
	}
	for k, f := range existing {
		if seen[k] {
			continue
		}
		resolved = append(resolved, f)
		if _, err := tx.ExecContext(ctx, `DELETE FROM findings WHERE host_id = ? AND vuln_id = ? AND package = ?`, hostID, k[0], k[1]); err != nil {
			return nil, nil, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO findings_resolved(host_id, vuln_id, package, installed, resolved_at) VALUES (?,?,?,?,?)`, hostID, k[0], k[1], f.Installed, now); err != nil {
			return nil, nil, err
		}
	}
	return added, resolved, tx.Commit()
}

const findingCols = `host_id, vuln_id, package, installed, fixed, advisory, binaries, exposed, severity, risk, risk_json, first_seen, last_seen`

func scanFinding(sc interface{ Scan(...any) error }) (StoredFinding, error) {
	var f StoredFinding
	var bins string
	var fs, ls int64
	err := sc.Scan(&f.HostID, &f.VulnID, &f.Package, &f.Installed, &f.Fixed, &f.Advisory, &bins, &f.Exposed, &f.Severity, &f.Risk, &f.RiskJSON, &fs, &ls)
	f.Binaries = SplitTags(bins)
	f.FirstSeen, f.LastSeen = time.Unix(fs, 0), time.Unix(ls, 0)
	return f, err
}

// FindingFilter selects findings.
type FindingFilter struct {
	HostID  string
	VulnID  string
	Package string
}

// ListFindings returns findings matching the filter, highest risk first.
func (d *DB) ListFindings(ctx context.Context, f FindingFilter) ([]StoredFinding, error) {
	q := `SELECT ` + findingCols + ` FROM findings WHERE 1=1`
	var args []any
	if f.HostID != "" {
		q += ` AND host_id = ?`
		args = append(args, f.HostID)
	}
	if f.VulnID != "" {
		q += ` AND vuln_id = ?`
		args = append(args, f.VulnID)
	}
	if f.Package != "" {
		q += ` AND (package = ? OR ',' || binaries || ',' LIKE ?)`
		args = append(args, f.Package, "%,"+f.Package+",%")
	}
	rows, err := d.sql.QueryContext(ctx, q+` ORDER BY risk DESC, vuln_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredFinding
	for rows.Next() {
		x, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// ResolvedFindings returns recently resolved findings of a host.
func (d *DB) ResolvedFindings(ctx context.Context, hostID string, limit int) ([]StoredFinding, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT vuln_id, package, installed, resolved_at FROM findings_resolved WHERE host_id = ? ORDER BY resolved_at DESC LIMIT ?`, hostID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredFinding
	for rows.Next() {
		var f StoredFinding
		var ts int64
		if err := rows.Scan(&f.VulnID, &f.Package, &f.Installed, &ts); err != nil {
			return nil, err
		}
		f.LastSeen = time.Unix(ts, 0)
		out = append(out, f)
	}
	return out, rows.Err()
}

// Exception is an accepted-risk or ignore decision.
type Exception struct {
	ID        string
	VulnID    string
	HostID    string
	Kind      string
	Reason    string
	ExpiresAt time.Time
	CreatedBy string
	CreatedAt time.Time
}

// Active reports whether the exception applies at t.
func (e Exception) Active(t time.Time) bool { return e.ExpiresAt.IsZero() || t.Before(e.ExpiresAt) }

// Covers reports whether the exception applies to a finding on hostID.
func (e Exception) Covers(hostID, vulnID string) bool {
	return e.VulnID == vulnID && (e.HostID == "" || e.HostID == hostID)
}

// CreateException stores an exception.
func (d *DB) CreateException(ctx context.Context, e Exception) (Exception, error) {
	e.ID, e.CreatedAt = uuid.NewString(), d.now()
	var exp int64
	if !e.ExpiresAt.IsZero() {
		exp = e.ExpiresAt.Unix()
	}
	_, err := d.sql.ExecContext(ctx, `INSERT INTO vuln_exceptions(id, vuln_id, host_id, kind, reason, expires_at, created_by, created_at) VALUES (?,?,?,?,?,?,?,?)`,
		e.ID, e.VulnID, e.HostID, e.Kind, e.Reason, exp, e.CreatedBy, e.CreatedAt.Unix())
	return e, err
}

// DeleteException removes an exception.
func (d *DB) DeleteException(ctx context.Context, id string) (Exception, error) {
	var e Exception
	err := d.sql.QueryRowContext(ctx, `SELECT id, vuln_id, host_id FROM vuln_exceptions WHERE id = ?`, id).Scan(&e.ID, &e.VulnID, &e.HostID)
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	if err != nil {
		return e, err
	}
	_, err = d.sql.ExecContext(ctx, `DELETE FROM vuln_exceptions WHERE id = ?`, id)
	return e, err
}

// ListExceptions returns exceptions (optionally for one vulnerability), including expired ones.
func (d *DB) ListExceptions(ctx context.Context, vulnID string) ([]Exception, error) {
	q := `SELECT id, vuln_id, host_id, kind, reason, expires_at, created_by, created_at FROM vuln_exceptions`
	var args []any
	if vulnID != "" {
		q += ` WHERE vuln_id = ?`
		args = append(args, vulnID)
	}
	rows, err := d.sql.QueryContext(ctx, q+` ORDER BY created_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Exception
	for rows.Next() {
		var e Exception
		var exp, c int64
		if err := rows.Scan(&e.ID, &e.VulnID, &e.HostID, &e.Kind, &e.Reason, &exp, &e.CreatedBy, &c); err != nil {
			return nil, err
		}
		if exp > 0 {
			e.ExpiresAt = time.Unix(exp, 0)
		}
		e.CreatedAt = time.Unix(c, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// FeedStatus tracks one feed's sync state.
type FeedStatus struct {
	Feed        string
	LastAttempt time.Time
	LastSuccess time.Time
	LastError   string
	Records     int
	ETag        string
}

// GetFeedStatus returns the status of all feeds.
func (d *DB) GetFeedStatus(ctx context.Context) (map[string]FeedStatus, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT feed, last_attempt, last_success, last_error, records, etag FROM feed_status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]FeedStatus{}
	for rows.Next() {
		var f FeedStatus
		var a, s int64
		if err := rows.Scan(&f.Feed, &a, &s, &f.LastError, &f.Records, &f.ETag); err != nil {
			return nil, err
		}
		if a > 0 {
			f.LastAttempt = time.Unix(a, 0)
		}
		if s > 0 {
			f.LastSuccess = time.Unix(s, 0)
		}
		out[f.Feed] = f
	}
	return out, rows.Err()
}

// RecordFeed stores the outcome of a sync attempt.
func (d *DB) RecordFeed(ctx context.Context, feed string, records int, etag string, syncErr error) error {
	now := d.now().Unix()
	if syncErr != nil {
		msg := syncErr.Error()
		if len(msg) > 500 {
			msg = msg[:500]
		}
		_, err := d.sql.ExecContext(ctx, `INSERT INTO feed_status(feed, last_attempt, last_error) VALUES (?,?,?)
			ON CONFLICT(feed) DO UPDATE SET last_attempt = excluded.last_attempt, last_error = excluded.last_error`, feed, now, msg)
		return err
	}
	_, err := d.sql.ExecContext(ctx, `INSERT INTO feed_status(feed, last_attempt, last_success, last_error, records, etag) VALUES (?,?,?,'',?,?)
		ON CONFLICT(feed) DO UPDATE SET last_attempt = excluded.last_attempt, last_success = excluded.last_success, last_error = '', records = excluded.records, etag = excluded.etag`,
		feed, now, now, records, etag)
	return err
}
