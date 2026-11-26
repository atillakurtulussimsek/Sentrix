package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// EnrollToken is a one-time agent enrolment token (only the hash is stored).
type EnrollToken struct {
	ID        string
	Note      string
	Group     string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    time.Time
	HostID    string
}

// Host is an enrolled machine.
type Host struct {
	ID           string
	Hostname     string
	MachineID    string
	CertSerial   string
	CertNotAfter time.Time
	Revoked      bool
	AgentVersion string
	BootTime     time.Time
	CreatedAt    time.Time
	LastSeen     time.Time
	Group        string
	Tags         []string
	StateJSON    string
	StateAt      time.Time
}

// Online reports whether the host was seen within timeout.
func (h Host) Online(now time.Time, timeout time.Duration) bool {
	return !h.Revoked && !h.LastSeen.IsZero() && now.Sub(h.LastSeen) <= timeout
}

// CreateEnrollToken stores a new token hash.
func (d *DB) CreateEnrollToken(ctx context.Context, tokenHash, note, group string, ttl time.Duration) (EnrollToken, error) {
	now := d.now()
	t := EnrollToken{ID: uuid.NewString(), Note: note, Group: group, CreatedAt: now, ExpiresAt: now.Add(ttl)}
	_, err := d.sql.ExecContext(ctx, `INSERT INTO enroll_tokens(id, token_hash, note, group_name, created_at, expires_at) VALUES (?,?,?,?,?,?)`,
		t.ID, tokenHash, note, group, now.Unix(), t.ExpiresAt.Unix())
	return t, err
}

// ListEnrollTokens returns all tokens, newest first.
func (d *DB) ListEnrollTokens(ctx context.Context) ([]EnrollToken, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT id, note, group_name, created_at, expires_at, used_at, COALESCE(host_id,'') FROM enroll_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnrollToken
	for rows.Next() {
		var t EnrollToken
		var c, e int64
		var u sql.NullInt64
		if err := rows.Scan(&t.ID, &t.Note, &t.Group, &c, &e, &u, &t.HostID); err != nil {
			return nil, err
		}
		t.CreatedAt, t.ExpiresAt = time.Unix(c, 0), time.Unix(e, 0)
		if u.Valid {
			t.UsedAt = time.Unix(u.Int64, 0)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteEnrollToken removes a token.
func (d *DB) DeleteEnrollToken(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM enroll_tokens WHERE id = ?`, id)
	return err
}

// ErrTokenInvalid means the token is unknown, expired or already used.
var ErrTokenInvalid = errors.New("enrolment token invalid, expired or already used")

// EnrollHost atomically consumes a token and creates the host record.
func (d *DB) EnrollHost(ctx context.Context, tokenHash string, h Host) (Host, error) {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return h, err
	}
	defer tx.Rollback() //nolint:errcheck
	now := d.now()
	var tokID, group string
	err = tx.QueryRowContext(ctx, `SELECT id, group_name FROM enroll_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`, tokenHash, now.Unix()).Scan(&tokID, &group)
	if errors.Is(err, sql.ErrNoRows) {
		return h, ErrTokenInvalid
	}
	if err != nil {
		return h, err
	}
	res, err := tx.ExecContext(ctx, `UPDATE enroll_tokens SET used_at = ?, host_id = ? WHERE id = ? AND used_at IS NULL`, now.Unix(), h.ID, tokID)
	if err != nil {
		return h, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return h, ErrTokenInvalid
	}
	h.CreatedAt, h.Group = now, group
	_, err = tx.ExecContext(ctx, `INSERT INTO hosts(id, hostname, machine_id, cert_serial, cert_not_after, created_at, group_name) VALUES (?,?,?,?,?,?,?)`,
		h.ID, h.Hostname, h.MachineID, h.CertSerial, h.CertNotAfter.Unix(), now.Unix(), group)
	if err != nil {
		return h, fmt.Errorf("insert host: %w", err)
	}
	return h, tx.Commit()
}

const hostCols = `id, hostname, machine_id, cert_serial, cert_not_after, revoked, agent_version, boot_time, created_at, last_seen, group_name, tags, state_json, state_at`

func scanHost(sc interface{ Scan(...any) error }) (Host, error) {
	var h Host
	var notAfter, boot, created, seen, stateAt int64
	var revoked int
	var tags string
	if err := sc.Scan(&h.ID, &h.Hostname, &h.MachineID, &h.CertSerial, &notAfter, &revoked, &h.AgentVersion, &boot, &created, &seen, &h.Group, &tags, &h.StateJSON, &stateAt); err != nil {
		return h, err
	}
	h.CertNotAfter, h.CreatedAt = time.Unix(notAfter, 0), time.Unix(created, 0)
	if boot > 0 {
		h.BootTime = time.Unix(boot, 0)
	}
	if seen > 0 {
		h.LastSeen = time.Unix(seen, 0)
	}
	if stateAt > 0 {
		h.StateAt = time.Unix(stateAt, 0)
	}
	h.Revoked = revoked != 0
	h.Tags = SplitTags(tags)
	return h, nil
}

// SplitTags parses a comma separated tag list.
func SplitTags(s string) []string {
	var out []string
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// GetHost returns a host by ID.
func (d *DB) GetHost(ctx context.Context, id string) (Host, error) {
	h, err := scanHost(d.sql.QueryRowContext(ctx, `SELECT `+hostCols+` FROM hosts WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return h, ErrNotFound
	}
	return h, err
}

// ListHosts returns all hosts ordered by hostname.
func (d *DB) ListHosts(ctx context.Context) ([]Host, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+hostCols+` FROM hosts ORDER BY hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// TouchHost records a heartbeat.
func (d *DB) TouchHost(ctx context.Context, id, hostname, agentVersion string, boot time.Time) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE hosts SET last_seen = ?, hostname = ?, agent_version = ?, boot_time = ? WHERE id = ?`,
		d.now().Unix(), hostname, agentVersion, boot.Unix(), id)
	return err
}

// MarkSeen updates last_seen only.
func (d *DB) MarkSeen(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE hosts SET last_seen = ? WHERE id = ?`, d.now().Unix(), id)
	return err
}

// UpdateHostCert records a renewed certificate.
func (d *DB) UpdateHostCert(ctx context.Context, id, serial string, notAfter time.Time) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE hosts SET cert_serial = ?, cert_not_after = ? WHERE id = ?`, serial, notAfter.Unix(), id)
	return err
}

// SetHostRevoked revokes or un-revokes a host's certificate.
func (d *DB) SetHostRevoked(ctx context.Context, id string, revoked bool) error {
	v := 0
	if revoked {
		v = 1
	}
	_, err := d.sql.ExecContext(ctx, `UPDATE hosts SET revoked = ? WHERE id = ?`, v, id)
	return err
}

// SetHostLabels updates group and tags.
func (d *DB) SetHostLabels(ctx context.Context, id, group string, tags []string) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE hosts SET group_name = ?, tags = ? WHERE id = ?`, group, strings.Join(tags, ","), id)
	return err
}

// SaveHostState stores the latest state snapshot JSON.
func (d *DB) SaveHostState(ctx context.Context, id, stateJSON string) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE hosts SET state_json = ?, state_at = ? WHERE id = ?`, stateJSON, d.now().Unix(), id)
	return err
}

// DeleteHost removes a host and (via cascades in later tables) its data.
func (d *DB) DeleteHost(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM hosts WHERE id = ?`, id)
	return err
}
