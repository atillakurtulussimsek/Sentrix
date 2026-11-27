package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

// CommandRow is a queued or finished agent command.
type CommandRow struct {
	ID         string
	HostID     string
	Action     protocol.Action
	Params     string
	DryRun     bool
	Status     string
	PlanID     string
	CreatedBy  string
	CreatedAt  time.Time
	SentAt     time.Time
	FinishedAt time.Time
	ExpiresAt  time.Time
	Result     *protocol.CommandResult
}

// EnqueueCommand validates and queues a command for a host.
func (d *DB) EnqueueCommand(ctx context.Context, hostID string, action protocol.Action, params any, dryRun bool, planID, by string, ttl time.Duration) (CommandRow, error) {
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return CommandRow{}, err
		}
		raw = b
	}
	c := CommandRow{ID: uuid.NewString(), HostID: hostID, Action: action, Params: string(raw), DryRun: dryRun, Status: "queued",
		PlanID: planID, CreatedBy: by, CreatedAt: d.now(), ExpiresAt: d.now().Add(ttl)}
	if err := (protocol.Command{ID: c.ID, Action: action, Params: raw}).Validate(); err != nil {
		return c, err
	}
	_, err := d.sql.ExecContext(ctx, `INSERT INTO commands(id, host_id, action, params, dry_run, status, plan_id, created_by, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		c.ID, hostID, string(action), c.Params, boolInt(dryRun), c.Status, planID, by, c.CreatedAt.Unix(), c.ExpiresAt.Unix())
	return c, err
}

// ClaimCommands returns commands to deliver to a host: queued ones, plus ones sent more
// than redeliverAfter ago without a result (agent may have crashed). They are marked sent.
func (d *DB) ClaimCommands(ctx context.Context, hostID string, redeliverAfter time.Duration) ([]protocol.Command, error) {
	now := d.now()
	if _, err := d.sql.ExecContext(ctx, `UPDATE commands SET status = 'expired', finished_at = ? WHERE host_id = ? AND status IN ('queued','sent') AND expires_at < ?`, now.Unix(), hostID, now.Unix()); err != nil {
		return nil, err
	}
	rows, err := d.sql.QueryContext(ctx, `SELECT id, action, params, dry_run, created_at FROM commands WHERE host_id = ? AND (status = 'queued' OR (status = 'sent' AND sent_at < ?)) ORDER BY created_at LIMIT 10`,
		hostID, now.Add(-redeliverAfter).Unix())
	if err != nil {
		return nil, err
	}
	var out []protocol.Command
	for rows.Next() {
		var c protocol.Command
		var params string
		var dry int
		var created int64
		if err := rows.Scan(&c.ID, &c.Action, &params, &dry, &created); err != nil {
			rows.Close()
			return nil, err
		}
		if params != "" {
			c.Params = json.RawMessage(params)
		}
		c.DryRun, c.IssuedAt = dry != 0, time.Unix(created, 0).UTC()
		out = append(out, c)
	}
	rows.Close()
	for _, c := range out {
		if _, err := d.sql.ExecContext(ctx, `UPDATE commands SET status = 'sent', sent_at = ? WHERE id = ?`, now.Unix(), c.ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// CompleteCommand stores a result reported by the host that owns the command.
func (d *DB) CompleteCommand(ctx context.Context, hostID string, r protocol.CommandResult) (CommandRow, error) {
	b, _ := json.Marshal(r)
	status := r.Status
	switch status {
	case protocol.StatusOK, protocol.StatusFailed, protocol.StatusRejected:
	default:
		status = protocol.StatusFailed
	}
	res, err := d.sql.ExecContext(ctx, `UPDATE commands SET status = ?, finished_at = ?, result = ? WHERE id = ? AND host_id = ? AND status IN ('queued','sent','expired')`,
		status, d.now().Unix(), string(b), r.ID, hostID)
	if err != nil {
		return CommandRow{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return CommandRow{}, ErrNotFound
	}
	return d.GetCommand(ctx, r.ID)
}

// GetCommand returns a command by ID.
func (d *DB) GetCommand(ctx context.Context, id string) (CommandRow, error) {
	rows, err := d.listCommands(ctx, `WHERE id = ?`, id)
	if err != nil {
		return CommandRow{}, err
	}
	if len(rows) == 0 {
		return CommandRow{}, ErrNotFound
	}
	return rows[0], nil
}

// ListHostCommands returns recent commands of a host.
func (d *DB) ListHostCommands(ctx context.Context, hostID string, limit int) ([]CommandRow, error) {
	return d.listCommands(ctx, `WHERE host_id = ? ORDER BY created_at DESC LIMIT ?`, hostID, limit)
}

func (d *DB) listCommands(ctx context.Context, where string, args ...any) ([]CommandRow, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT id, host_id, action, params, dry_run, status, plan_id, created_by, created_at, sent_at, finished_at, expires_at, result FROM commands `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CommandRow
	for rows.Next() {
		var c CommandRow
		var dry int
		var cr, se, fi, ex int64
		var result string
		if err := rows.Scan(&c.ID, &c.HostID, &c.Action, &c.Params, &dry, &c.Status, &c.PlanID, &c.CreatedBy, &cr, &se, &fi, &ex, &result); err != nil {
			return nil, err
		}
		c.DryRun, c.CreatedAt, c.ExpiresAt = dry != 0, time.Unix(cr, 0), time.Unix(ex, 0)
		if se > 0 {
			c.SentAt = time.Unix(se, 0)
		}
		if fi > 0 {
			c.FinishedAt = time.Unix(fi, 0)
		}
		if result != "" {
			var r protocol.CommandResult
			if json.Unmarshal([]byte(result), &r) == nil {
				c.Result = &r
			}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// errNoRows maps sql.ErrNoRows to ErrNotFound.
func errNoRows(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// LastHostCommand returns the most recent command of the given action for a host.
func (d *DB) LastHostCommand(ctx context.Context, hostID string, action protocol.Action) (CommandRow, bool, error) {
	rows, err := d.listCommands(ctx, `WHERE host_id = ? AND action = ? ORDER BY created_at DESC LIMIT 1`, hostID, string(action))
	if err != nil || len(rows) == 0 {
		return CommandRow{}, false, err
	}
	return rows[0], true, nil
}
