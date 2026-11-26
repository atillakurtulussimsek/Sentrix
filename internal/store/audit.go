package store

import (
	"context"
	"time"
)

// AuditEntry is one row of the append-only audit log.
type AuditEntry struct {
	ID     int64
	TS     time.Time
	Actor  string
	Action string
	Target string
	Detail string
}

// Audit appends an entry to the audit log.
func (d *DB) Audit(ctx context.Context, actor, action, target, detail string) error {
	_, err := d.sql.ExecContext(ctx, `INSERT INTO audit_log(ts, actor, action, target, detail) VALUES (?,?,?,?,?)`,
		d.now().Unix(), actor, action, target, detail)
	return err
}

// ListAudit returns the newest entries, optionally filtered by target.
func (d *DB) ListAudit(ctx context.Context, target string, limit int) ([]AuditEntry, error) {
	q := `SELECT id, ts, actor, action, target, detail FROM audit_log`
	args := []any{}
	if target != "" {
		q += ` WHERE target = ?`
		args = append(args, target)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := d.sql.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		e.TS = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}
