package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Channel is a notification channel (config JSON has secrets sealed).
type Channel struct {
	ID        string
	Name      string
	Kind      string
	Config    string
	Enabled   bool
	CreatedAt time.Time
}

// SaveChannel inserts or updates a channel.
func (d *DB) SaveChannel(ctx context.Context, c Channel) (Channel, error) {
	if c.ID == "" {
		c.ID, c.CreatedAt = uuid.NewString(), d.now()
		_, err := d.sql.ExecContext(ctx, `INSERT INTO channels(id, name, kind, config, enabled, created_at) VALUES (?,?,?,?,?,?)`, c.ID, c.Name, c.Kind, c.Config, boolInt(c.Enabled), c.CreatedAt.Unix())
		return c, err
	}
	_, err := d.sql.ExecContext(ctx, `UPDATE channels SET name = ?, kind = ?, config = ?, enabled = ? WHERE id = ?`, c.Name, c.Kind, c.Config, boolInt(c.Enabled), c.ID)
	return c, err
}

// ListChannels returns all channels.
func (d *DB) ListChannels(ctx context.Context) ([]Channel, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT id, name, kind, config, enabled, created_at FROM channels ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Channel
	for rows.Next() {
		var c Channel
		var en int
		var cr int64
		if err := rows.Scan(&c.ID, &c.Name, &c.Kind, &c.Config, &en, &cr); err != nil {
			return nil, err
		}
		c.Enabled, c.CreatedAt = en != 0, time.Unix(cr, 0)
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteChannel removes a channel.
func (d *DB) DeleteChannel(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM channels WHERE id = ?`, id)
	return err
}

// Rule is an alert rule.
type Rule struct {
	ID        string
	Name      string
	Kind      string
	Config    string
	Severity  string
	Channels  []string
	For       time.Duration
	Cooldown  time.Duration
	Enabled   bool
	CreatedAt time.Time
}

// SaveRule inserts or updates a rule.
func (d *DB) SaveRule(ctx context.Context, r Rule) (Rule, error) {
	ch := joinComma(r.Channels)
	if r.ID == "" {
		r.ID, r.CreatedAt = uuid.NewString(), d.now()
		_, err := d.sql.ExecContext(ctx, `INSERT INTO alert_rules(id, name, kind, config, severity, channels, for_seconds, cooldown_seconds, enabled, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
			r.ID, r.Name, r.Kind, r.Config, r.Severity, ch, int64(r.For.Seconds()), int64(r.Cooldown.Seconds()), boolInt(r.Enabled), r.CreatedAt.Unix())
		return r, err
	}
	_, err := d.sql.ExecContext(ctx, `UPDATE alert_rules SET name = ?, kind = ?, config = ?, severity = ?, channels = ?, for_seconds = ?, cooldown_seconds = ?, enabled = ? WHERE id = ?`,
		r.Name, r.Kind, r.Config, r.Severity, ch, int64(r.For.Seconds()), int64(r.Cooldown.Seconds()), boolInt(r.Enabled), r.ID)
	return r, err
}

func joinComma(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += ","
		}
		out += x
	}
	return out
}

// ListRules returns all rules.
func (d *DB) ListRules(ctx context.Context) ([]Rule, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT id, name, kind, config, severity, channels, for_seconds, cooldown_seconds, enabled, created_at FROM alert_rules ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		var ch string
		var f, c, cr int64
		var en int
		if err := rows.Scan(&r.ID, &r.Name, &r.Kind, &r.Config, &r.Severity, &ch, &f, &c, &en, &cr); err != nil {
			return nil, err
		}
		r.Channels, r.For, r.Cooldown, r.Enabled, r.CreatedAt = SplitTags(ch), time.Duration(f)*time.Second, time.Duration(c)*time.Second, en != 0, time.Unix(cr, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteRule removes a rule (and its alerts).
func (d *DB) DeleteRule(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM alert_rules WHERE id = ?`, id)
	return err
}

// Alert is an alert instance.
type Alert struct {
	ID           string
	RuleID       string
	HostID       string
	Key          string
	Status       string
	Severity     string
	Subject      string
	Message      string
	Value        float64
	StartedAt    time.Time
	FiredAt      time.Time
	ResolvedAt   time.Time
	LastNotified time.Time
}

const alertCols = `id, rule_id, host_id, dedup_key, status, severity, subject, message, value, started_at, fired_at, resolved_at, last_notified`

func scanAlert(sc interface{ Scan(...any) error }) (Alert, error) {
	var a Alert
	var s, f, r, l int64
	err := sc.Scan(&a.ID, &a.RuleID, &a.HostID, &a.Key, &a.Status, &a.Severity, &a.Subject, &a.Message, &a.Value, &s, &f, &r, &l)
	a.StartedAt = time.Unix(s, 0)
	for _, x := range []struct {
		v int64
		t *time.Time
	}{{f, &a.FiredAt}, {r, &a.ResolvedAt}, {l, &a.LastNotified}} {
		if x.v > 0 {
			*x.t = time.Unix(x.v, 0)
		}
	}
	return a, err
}

// OpenAlerts returns pending and firing alerts keyed by dedup key.
func (d *DB) OpenAlerts(ctx context.Context) (map[string]Alert, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+alertCols+` FROM alerts WHERE status IN ('pending','firing')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Alert{}
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out[a.Key] = a
	}
	return out, rows.Err()
}

// ListAlerts returns alerts by status (empty = all), newest first.
func (d *DB) ListAlerts(ctx context.Context, status string, limit int) ([]Alert, error) {
	q := `SELECT ` + alertCols + ` FROM alerts`
	var args []any
	if status != "" {
		q += ` WHERE status = ?`
		args = append(args, status)
	}
	args = append(args, limit)
	rows, err := d.sql.QueryContext(ctx, q+` ORDER BY started_at DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CountFiring returns the number of firing alerts.
func (d *DB) CountFiring(ctx context.Context) (int, error) {
	var n int
	err := d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE status = 'firing'`).Scan(&n)
	return n, err
}

// SaveAlert inserts or updates an alert.
func (d *DB) SaveAlert(ctx context.Context, a Alert) (Alert, error) {
	ts := func(t time.Time) int64 {
		if t.IsZero() {
			return 0
		}
		return t.Unix()
	}
	if a.ID == "" {
		a.ID = uuid.NewString()
		_, err := d.sql.ExecContext(ctx, `INSERT INTO alerts(`+alertCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`, a.ID, a.RuleID, a.HostID, a.Key, a.Status, a.Severity,
			a.Subject, a.Message, a.Value, ts(a.StartedAt), ts(a.FiredAt), ts(a.ResolvedAt), ts(a.LastNotified))
		return a, err
	}
	_, err := d.sql.ExecContext(ctx, `UPDATE alerts SET status = ?, severity = ?, subject = ?, message = ?, value = ?, fired_at = ?, resolved_at = ?, last_notified = ? WHERE id = ?`,
		a.Status, a.Severity, a.Subject, a.Message, a.Value, ts(a.FiredAt), ts(a.ResolvedAt), ts(a.LastNotified), a.ID)
	return a, err
}

// DeleteAlert removes an alert (pending alerts that never fired).
func (d *DB) DeleteAlert(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM alerts WHERE id = ?`, id)
	return err
}

// LastFiredNotification returns when a firing notification was last sent for a key.
func (d *DB) LastFiredNotification(ctx context.Context, key string) (time.Time, error) {
	var ts int64
	err := d.sql.QueryRowContext(ctx, `SELECT last_fired FROM alert_notify_state WHERE dedup_key = ?`, key).Scan(&ts)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	return time.Unix(ts, 0), err
}

// SetLastFiredNotification records a firing notification for a key.
func (d *DB) SetLastFiredNotification(ctx context.Context, key string, t time.Time) error {
	_, err := d.sql.ExecContext(ctx, `INSERT INTO alert_notify_state(dedup_key, last_fired) VALUES (?,?) ON CONFLICT(dedup_key) DO UPDATE SET last_fired = excluded.last_fired`, key, t.Unix())
	return err
}

// NotificationLog is one delivery attempt.
type NotificationLog struct {
	TS        time.Time
	ChannelID string
	AlertID   string
	Kind      string
	Status    string
	Error     string
}

// LogNotification records a delivery attempt.
func (d *DB) LogNotification(ctx context.Context, n NotificationLog) error {
	_, err := d.sql.ExecContext(ctx, `INSERT INTO notification_log(ts, channel_id, alert_id, kind, status, error) VALUES (?,?,?,?,?,?)`,
		d.now().Unix(), n.ChannelID, n.AlertID, n.Kind, n.Status, n.Error)
	return err
}

// ListNotifications returns recent delivery attempts.
func (d *DB) ListNotifications(ctx context.Context, limit int) ([]NotificationLog, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT ts, channel_id, alert_id, kind, status, error FROM notification_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NotificationLog
	for rows.Next() {
		var n NotificationLog
		var ts int64
		if err := rows.Scan(&ts, &n.ChannelID, &n.AlertID, &n.Kind, &n.Status, &n.Error); err != nil {
			return nil, err
		}
		n.TS = time.Unix(ts, 0)
		out = append(out, n)
	}
	return out, rows.Err()
}
