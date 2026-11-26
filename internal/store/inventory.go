package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

// HostInventory is the stored inventory header of a host.
type HostInventory struct {
	HostID         string
	CollectedAt    time.Time
	ReceivedAt     time.Time
	OS             protocol.OSInfo
	PackageManager string
	Errors         []string
}

// SaveInventory replaces a host's inventory atomically.
func (d *DB) SaveInventory(ctx context.Context, hostID string, inv protocol.Inventory) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	o := inv.OS
	if _, err := tx.ExecContext(ctx, `INSERT INTO host_inventory(host_id, collected_at, received_at, os_id, os_version, os_codename, os_pretty, kernel, arch, virtualization, package_manager, errors)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(host_id) DO UPDATE SET collected_at=excluded.collected_at, received_at=excluded.received_at, os_id=excluded.os_id, os_version=excluded.os_version,
		os_codename=excluded.os_codename, os_pretty=excluded.os_pretty, kernel=excluded.kernel, arch=excluded.arch, virtualization=excluded.virtualization,
		package_manager=excluded.package_manager, errors=excluded.errors`,
		hostID, inv.CollectedAt.Unix(), d.now().Unix(), o.ID, o.VersionID, o.Codename, o.PrettyName, o.Kernel, o.Arch, o.Virtualization, inv.PackageManager, strings.Join(inv.Errors, "\n")); err != nil {
		return err
	}
	for _, t := range []string{"packages", "updates", "ports", "host_images"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+t+` WHERE host_id = ?`, hostID); err != nil {
			return err
		}
	}
	ins, err := tx.PrepareContext(ctx, `INSERT INTO packages(host_id, name, arch, version, source, source_ver) VALUES (?,?,?,?,?,?) ON CONFLICT DO NOTHING`)
	if err != nil {
		return err
	}
	defer ins.Close()
	for _, p := range inv.Packages {
		if _, err := ins.ExecContext(ctx, hostID, p.Name, p.Arch, p.Version, p.SourceName, p.SourceVer); err != nil {
			return err
		}
	}
	for _, u := range inv.Updates {
		if _, err := tx.ExecContext(ctx, `INSERT INTO updates(host_id, name, current, new, security, origin) VALUES (?,?,?,?,?,?) ON CONFLICT DO NOTHING`,
			hostID, u.Name, u.CurrentVer, u.NewVer, boolInt(u.Security), u.Origin); err != nil {
			return err
		}
	}
	for _, p := range inv.Ports {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ports(host_id, proto, address, port, pid, process) VALUES (?,?,?,?,?,?) ON CONFLICT DO NOTHING`,
			hostID, p.Proto, p.Address, p.Port, p.PID, p.Process); err != nil {
			return err
		}
	}
	for _, im := range inv.Images {
		if _, err := tx.ExecContext(ctx, `INSERT INTO host_images(host_id, image) VALUES (?,?) ON CONFLICT DO NOTHING`, hostID, im); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// GetInventory returns the inventory header of a host.
func (d *DB) GetInventory(ctx context.Context, hostID string) (HostInventory, error) {
	var h HostInventory
	var c, r int64
	var errs string
	err := d.sql.QueryRowContext(ctx, `SELECT host_id, collected_at, received_at, os_id, os_version, os_codename, os_pretty, kernel, arch, virtualization, package_manager, errors FROM host_inventory WHERE host_id = ?`, hostID).
		Scan(&h.HostID, &c, &r, &h.OS.ID, &h.OS.VersionID, &h.OS.Codename, &h.OS.PrettyName, &h.OS.Kernel, &h.OS.Arch, &h.OS.Virtualization, &h.PackageManager, &errs)
	if errors.Is(err, sql.ErrNoRows) {
		return h, ErrNotFound
	}
	h.CollectedAt, h.ReceivedAt = time.Unix(c, 0), time.Unix(r, 0)
	if errs != "" {
		h.Errors = strings.Split(errs, "\n")
	}
	return h, err
}

// ListInventories returns all inventory headers keyed by host.
func (d *DB) ListInventories(ctx context.Context) (map[string]HostInventory, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT host_id, collected_at, os_id, os_version, os_codename, os_pretty, kernel, package_manager FROM host_inventory`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]HostInventory{}
	for rows.Next() {
		var h HostInventory
		var c int64
		if err := rows.Scan(&h.HostID, &c, &h.OS.ID, &h.OS.VersionID, &h.OS.Codename, &h.OS.PrettyName, &h.OS.Kernel, &h.PackageManager); err != nil {
			return nil, err
		}
		h.CollectedAt = time.Unix(c, 0)
		out[h.HostID] = h
	}
	return out, rows.Err()
}

// ListPackages returns installed packages of a host, optionally filtered by substring.
func (d *DB) ListPackages(ctx context.Context, hostID, q string) ([]protocol.Package, error) {
	sq := `SELECT name, arch, version, source, source_ver FROM packages WHERE host_id = ?`
	args := []any{hostID}
	if q != "" {
		sq += ` AND (name LIKE ? OR source LIKE ?)`
		args = append(args, "%"+q+"%", "%"+q+"%")
	}
	rows, err := d.sql.QueryContext(ctx, sq+` ORDER BY name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.Package
	for rows.Next() {
		var p protocol.Package
		if err := rows.Scan(&p.Name, &p.Arch, &p.Version, &p.SourceName, &p.SourceVer); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListUpdates returns pending updates of a host (security first).
func (d *DB) ListUpdates(ctx context.Context, hostID string) ([]protocol.Update, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT name, current, new, security, origin FROM updates WHERE host_id = ? ORDER BY security DESC, name`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.Update
	for rows.Next() {
		var u protocol.Update
		var sec int
		if err := rows.Scan(&u.Name, &u.CurrentVer, &u.NewVer, &sec, &u.Origin); err != nil {
			return nil, err
		}
		u.Security = sec != 0
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateCounts returns (total, security) pending updates per host.
func (d *DB) UpdateCounts(ctx context.Context) (map[string][2]int, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT host_id, COUNT(*), SUM(security) FROM updates GROUP BY host_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][2]int{}
	for rows.Next() {
		var h string
		var n, s int
		if err := rows.Scan(&h, &n, &s); err != nil {
			return nil, err
		}
		out[h] = [2]int{n, s}
	}
	return out, rows.Err()
}

// MarkSecurityUpdates flags updates of the given packages as security-relevant
// (used for apk, whose metadata has no security classification).
func (d *DB) MarkSecurityUpdates(ctx context.Context, hostID string, names []string) error {
	for _, n := range names {
		if _, err := d.sql.ExecContext(ctx, `UPDATE updates SET security = 1 WHERE host_id = ? AND name = ?`, hostID, n); err != nil {
			return err
		}
	}
	return nil
}

// ListPorts returns listening ports of a host.
func (d *DB) ListPorts(ctx context.Context, hostID string) ([]protocol.ListeningPort, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT proto, address, port, pid, process FROM ports WHERE host_id = ? ORDER BY port, proto`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.ListeningPort
	for rows.Next() {
		var p protocol.ListeningPort
		if err := rows.Scan(&p.Proto, &p.Address, &p.Port, &p.PID, &p.Process); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListImages returns container images seen on a host.
func (d *DB) ListImages(ctx context.Context, hostID string) ([]string, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT image FROM host_images WHERE host_id = ? ORDER BY image`, hostID)
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

// CountPackages returns the number of installed packages per host.
func (d *DB) CountPackages(ctx context.Context, hostID string) (int, error) {
	var n int
	err := d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM packages WHERE host_id = ?`, hostID).Scan(&n)
	return n, err
}
