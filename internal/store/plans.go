package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

// Plan is a patch plan.
type Plan struct {
	ID               string
	Name             string
	Scope            string
	Packages         []string
	Status           string
	PolicyID         string
	Reboot           string
	Canary           int
	MaxParallel      int
	SnapshotHook     string
	SnapshotRequired bool
	CreatedBy        string
	ApprovedBy       string
	CreatedAt        time.Time
	ApprovedAt       time.Time
	StartedAt        time.Time
	FinishedAt       time.Time
	Error            string
}

// PlanHost is one host's progress within a plan.
type PlanHost struct {
	PlanID         string
	HostID         string
	Hostname       string
	Position       int
	Status         string
	StepCmd        string
	DryChanges     []protocol.PackageChange
	Changes        []protocol.PackageChange
	Output         string
	Error          string
	FindingsBefore int
	FindingsAfter  int
	RebootRequired bool
	BootTimeBefore time.Time
	Snapshot       string
	StartedAt      time.Time
	FinishedAt     time.Time
	StepStarted    time.Time
}

// Terminal plan-host states.
func (h PlanHost) Terminal() bool {
	return h.Status == "done" || h.Status == "failed" || h.Status == "skipped"
}

// CreatePlan stores a plan with its hosts (ordered).
func (d *DB) CreatePlan(ctx context.Context, p Plan, hostIDs []string) (Plan, error) {
	p.ID, p.CreatedAt = uuid.NewString(), d.now()
	if p.Status == "" {
		p.Status = "draft"
	}
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return p, err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, `INSERT INTO patch_plans(id, name, scope, packages, status, policy_id, reboot, canary, max_parallel, snapshot_hook, snapshot_required, created_by, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`, p.ID, p.Name, p.Scope, strings.Join(p.Packages, ","), p.Status, p.PolicyID, p.Reboot, p.Canary, p.MaxParallel,
		p.SnapshotHook, boolInt(p.SnapshotRequired), p.CreatedBy, p.CreatedAt.Unix()); err != nil {
		return p, err
	}
	for i, h := range hostIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO plan_hosts(plan_id, host_id, position) VALUES (?,?,?)`, p.ID, h, i); err != nil {
			return p, err
		}
	}
	return p, tx.Commit()
}

const planCols = `id, name, scope, packages, status, policy_id, reboot, canary, max_parallel, snapshot_hook, snapshot_required, created_by, approved_by, created_at, approved_at, started_at, finished_at, error`

func scanPlan(sc interface{ Scan(...any) error }) (Plan, error) {
	var p Plan
	var pk string
	var snap int
	var c, a, s, f int64
	err := sc.Scan(&p.ID, &p.Name, &p.Scope, &pk, &p.Status, &p.PolicyID, &p.Reboot, &p.Canary, &p.MaxParallel, &p.SnapshotHook, &snap, &p.CreatedBy, &p.ApprovedBy, &c, &a, &s, &f, &p.Error)
	p.Packages, p.SnapshotRequired = SplitTags(pk), snap != 0
	p.CreatedAt = time.Unix(c, 0)
	for _, x := range []struct {
		v int64
		t *time.Time
	}{{a, &p.ApprovedAt}, {s, &p.StartedAt}, {f, &p.FinishedAt}} {
		if x.v > 0 {
			*x.t = time.Unix(x.v, 0)
		}
	}
	return p, err
}

// GetPlan returns a plan.
func (d *DB) GetPlan(ctx context.Context, id string) (Plan, error) {
	p, err := scanPlan(d.sql.QueryRowContext(ctx, `SELECT `+planCols+` FROM patch_plans WHERE id = ?`, id))
	return p, errNoRows(err)
}

// ListPlans returns plans, newest first (optionally only given statuses).
func (d *DB) ListPlans(ctx context.Context, statuses ...string) ([]Plan, error) {
	q := `SELECT ` + planCols + ` FROM patch_plans`
	var args []any
	if len(statuses) > 0 {
		q += ` WHERE status IN (?` + strings.Repeat(",?", len(statuses)-1) + `)`
		for _, s := range statuses {
			args = append(args, s)
		}
	}
	rows, err := d.sql.QueryContext(ctx, q+` ORDER BY created_at DESC LIMIT 500`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Plan
	for rows.Next() {
		p, err := scanPlan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpdatePlanStatus sets status (and timestamps/approver as appropriate).
func (d *DB) UpdatePlanStatus(ctx context.Context, id, status, errMsg string) error {
	now := d.now().Unix()
	q := `UPDATE patch_plans SET status = ?, error = ?`
	switch status {
	case "running":
		q += `, started_at = CASE WHEN started_at = 0 THEN ` + itoa64(now) + ` ELSE started_at END`
	case "done", "failed", "cancelled":
		q += `, finished_at = ` + itoa64(now)
	}
	_, err := d.sql.ExecContext(ctx, q+` WHERE id = ?`, status, errMsg, id)
	return err
}

// ApprovePlan marks a ready plan as approved.
func (d *DB) ApprovePlan(ctx context.Context, id, by string) (bool, error) {
	res, err := d.sql.ExecContext(ctx, `UPDATE patch_plans SET status = 'approved', approved_by = ?, approved_at = ? WHERE id = ? AND status = 'ready'`, by, d.now().Unix(), id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func itoa64(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// ListPlanHosts returns plan hosts in order.
func (d *DB) ListPlanHosts(ctx context.Context, planID string) ([]PlanHost, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT ph.plan_id, ph.host_id, COALESCE(h.hostname, ph.host_id), ph.position, ph.status, ph.step_cmd, ph.dry_changes, ph.changes, ph.output, ph.error,
		ph.findings_before, ph.findings_after, ph.reboot_required, ph.boot_time_before, ph.snapshot, ph.started_at, ph.finished_at, ph.step_started
		FROM plan_hosts ph LEFT JOIN hosts h ON h.id = ph.host_id WHERE ph.plan_id = ? ORDER BY ph.position`, planID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PlanHost
	for rows.Next() {
		var h PlanHost
		var dry, ch string
		var rb int
		var boot, s, f, st int64
		if err := rows.Scan(&h.PlanID, &h.HostID, &h.Hostname, &h.Position, &h.Status, &h.StepCmd, &dry, &ch, &h.Output, &h.Error,
			&h.FindingsBefore, &h.FindingsAfter, &rb, &boot, &h.Snapshot, &s, &f, &st); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(dry), &h.DryChanges)
		_ = json.Unmarshal([]byte(ch), &h.Changes)
		h.RebootRequired = rb != 0
		for _, x := range []struct {
			v int64
			t *time.Time
		}{{boot, &h.BootTimeBefore}, {s, &h.StartedAt}, {f, &h.FinishedAt}, {st, &h.StepStarted}} {
			if x.v > 0 {
				*x.t = time.Unix(x.v, 0)
			}
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// SavePlanHost persists a plan host's mutable fields.
func (d *DB) SavePlanHost(ctx context.Context, h PlanHost) error {
	dry, _ := json.Marshal(h.DryChanges)
	ch, _ := json.Marshal(h.Changes)
	ts := func(t time.Time) int64 {
		if t.IsZero() {
			return 0
		}
		return t.Unix()
	}
	_, err := d.sql.ExecContext(ctx, `UPDATE plan_hosts SET status = ?, step_cmd = ?, dry_changes = ?, changes = ?, output = ?, error = ?, findings_before = ?, findings_after = ?,
		reboot_required = ?, boot_time_before = ?, snapshot = ?, started_at = ?, finished_at = ?, step_started = ? WHERE plan_id = ? AND host_id = ?`,
		h.Status, h.StepCmd, string(dry), string(ch), h.Output, h.Error, h.FindingsBefore, h.FindingsAfter, boolInt(h.RebootRequired), ts(h.BootTimeBefore),
		h.Snapshot, ts(h.StartedAt), ts(h.FinishedAt), ts(h.StepStarted), h.PlanID, h.HostID)
	return err
}

// HostPlans returns plans that include a host.
func (d *DB) HostPlans(ctx context.Context, hostID string) ([]Plan, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+prefixCols("p.", planCols)+` FROM patch_plans p JOIN plan_hosts ph ON ph.plan_id = p.id WHERE ph.host_id = ? ORDER BY p.created_at DESC LIMIT 50`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Plan
	for rows.Next() {
		p, err := scanPlan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func prefixCols(prefix, cols string) string {
	parts := strings.Split(cols, ",")
	for i, p := range parts {
		parts[i] = prefix + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}

// CountFindings returns the number of current findings of a host.
func (d *DB) CountFindings(ctx context.Context, hostID string) (int, error) {
	var n int
	err := d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE host_id = ?`, hostID).Scan(&n)
	return n, err
}

// Policy is a per-group patch policy.
type Policy struct {
	ID               string
	Name             string
	Group            string
	Mode             string
	WindowCron       string
	WindowMinutes    int
	MaxParallel      int
	Canary           int
	Reboot           string
	SnapshotHook     string
	SnapshotRequired bool
	Enabled          bool
	LastRun          time.Time
}

const policyCols = `id, name, group_name, mode, window_cron, window_minutes, max_parallel, canary, reboot, snapshot_hook, snapshot_required, enabled, last_run`

// SavePolicy inserts or updates a policy.
func (d *DB) SavePolicy(ctx context.Context, p Policy) (Policy, error) {
	now := d.now().Unix()
	if p.ID == "" {
		p.ID = uuid.NewString()
		_, err := d.sql.ExecContext(ctx, `INSERT INTO policies(id, name, group_name, mode, window_cron, window_minutes, max_parallel, canary, reboot, snapshot_hook, snapshot_required, enabled, created_at, updated_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, p.ID, p.Name, p.Group, p.Mode, p.WindowCron, p.WindowMinutes, p.MaxParallel, p.Canary, p.Reboot, p.SnapshotHook,
			boolInt(p.SnapshotRequired), boolInt(p.Enabled), now, now)
		return p, err
	}
	_, err := d.sql.ExecContext(ctx, `UPDATE policies SET name = ?, group_name = ?, mode = ?, window_cron = ?, window_minutes = ?, max_parallel = ?, canary = ?, reboot = ?,
		snapshot_hook = ?, snapshot_required = ?, enabled = ?, updated_at = ? WHERE id = ?`, p.Name, p.Group, p.Mode, p.WindowCron, p.WindowMinutes, p.MaxParallel, p.Canary,
		p.Reboot, p.SnapshotHook, boolInt(p.SnapshotRequired), boolInt(p.Enabled), now, p.ID)
	return p, err
}

// ListPolicies returns all policies.
func (d *DB) ListPolicies(ctx context.Context) ([]Policy, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+policyCols+` FROM policies ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Policy
	for rows.Next() {
		var p Policy
		var snap, en int
		var lr int64
		if err := rows.Scan(&p.ID, &p.Name, &p.Group, &p.Mode, &p.WindowCron, &p.WindowMinutes, &p.MaxParallel, &p.Canary, &p.Reboot, &p.SnapshotHook, &snap, &en, &lr); err != nil {
			return nil, err
		}
		p.SnapshotRequired, p.Enabled = snap != 0, en != 0
		if lr > 0 {
			p.LastRun = time.Unix(lr, 0)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeletePolicy removes a policy.
func (d *DB) DeletePolicy(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM policies WHERE id = ?`, id)
	return err
}

// TouchPolicy records a policy run.
func (d *DB) TouchPolicy(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE policies SET last_run = ? WHERE id = ?`, d.now().Unix(), id)
	return err
}

// HostSettings holds per-host configuration.
type HostSettings struct {
	WatchServices []string
	TLSEndpoints  []string
	ProxmoxVMID   string
	ProxmoxNode   string
}

// GetHostSettings returns per-host settings (zero value if unset).
func (d *DB) GetHostSettings(ctx context.Context, hostID string) (HostSettings, error) {
	var s HostSettings
	var ws, te string
	err := d.sql.QueryRowContext(ctx, `SELECT watch_services, tls_endpoints, proxmox_vmid, proxmox_node FROM host_settings WHERE host_id = ?`, hostID).Scan(&ws, &te, &s.ProxmoxVMID, &s.ProxmoxNode)
	if errors.Is(errNoRows(err), ErrNotFound) {
		return s, nil
	}
	s.WatchServices, s.TLSEndpoints = SplitTags(ws), SplitTags(te)
	return s, err
}

// SaveHostSettings upserts per-host settings.
func (d *DB) SaveHostSettings(ctx context.Context, hostID string, s HostSettings) error {
	_, err := d.sql.ExecContext(ctx, `INSERT INTO host_settings(host_id, watch_services, tls_endpoints, proxmox_vmid, proxmox_node) VALUES (?,?,?,?,?)
		ON CONFLICT(host_id) DO UPDATE SET watch_services = excluded.watch_services, tls_endpoints = excluded.tls_endpoints, proxmox_vmid = excluded.proxmox_vmid, proxmox_node = excluded.proxmox_node`,
		hostID, strings.Join(s.WatchServices, ","), strings.Join(s.TLSEndpoints, ","), s.ProxmoxVMID, s.ProxmoxNode)
	return err
}

// Hook is a pre-patch hook definition.
type Hook struct {
	ID        string
	Name      string
	Kind      string
	Config    string // JSON with sealed secrets
	CreatedAt time.Time
}

// SaveHook inserts or updates a hook.
func (d *DB) SaveHook(ctx context.Context, h Hook) (Hook, error) {
	if h.ID == "" {
		h.ID, h.CreatedAt = uuid.NewString(), d.now()
		_, err := d.sql.ExecContext(ctx, `INSERT INTO hooks(id, name, kind, config, created_at) VALUES (?,?,?,?,?)`, h.ID, h.Name, h.Kind, h.Config, h.CreatedAt.Unix())
		return h, err
	}
	_, err := d.sql.ExecContext(ctx, `UPDATE hooks SET name = ?, kind = ?, config = ? WHERE id = ?`, h.Name, h.Kind, h.Config, h.ID)
	return h, err
}

// ListHooks returns hooks.
func (d *DB) ListHooks(ctx context.Context) ([]Hook, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT id, name, kind, config, created_at FROM hooks ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Hook
	for rows.Next() {
		var h Hook
		var c int64
		if err := rows.Scan(&h.ID, &h.Name, &h.Kind, &h.Config, &c); err != nil {
			return nil, err
		}
		h.CreatedAt = time.Unix(c, 0)
		out = append(out, h)
	}
	return out, rows.Err()
}

// GetHook returns one hook.
func (d *DB) GetHook(ctx context.Context, id string) (Hook, error) {
	var h Hook
	var c int64
	err := d.sql.QueryRowContext(ctx, `SELECT id, name, kind, config, created_at FROM hooks WHERE id = ?`, id).Scan(&h.ID, &h.Name, &h.Kind, &h.Config, &c)
	h.CreatedAt = time.Unix(c, 0)
	return h, errNoRows(err)
}

// DeleteHook removes a hook.
func (d *DB) DeleteHook(ctx context.Context, id string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM hooks WHERE id = ?`, id)
	return err
}
