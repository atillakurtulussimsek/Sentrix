package store

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

// MetricStore abstracts time-series storage so a dedicated TSDB can replace SQLite later.
type MetricStore interface {
	Ingest(ctx context.Context, hostID string, samples []protocol.Sample) error
	Query(ctx context.Context, q MetricQuery) ([]Series, error)
	Latest(ctx context.Context, hostID string) (map[string]float64, error)
	Rollup(ctx context.Context, now time.Time) error
	Prune(ctx context.Context, now time.Time, raw, minute, hour time.Duration) error
}

// MetricQuery selects series of one host.
type MetricQuery struct {
	HostID string
	Name   string
	Labels *string // nil = all label sets
	From   time.Time
	To     time.Time
	// Resolution: "raw", "1m", "1h" or "" for automatic choice by range.
	Resolution string
}

// Point is one value at a timestamp (unix seconds).
type Point struct {
	TS    int64   `json:"t"`
	Value float64 `json:"v"`
}

// Series is a named, labelled list of points.
type Series struct {
	Name   string  `json:"name"`
	Labels string  `json:"labels"`
	Points []Point `json:"points"`
}

type seriesKey struct{ host, name, labels string }

// SQLMetrics implements MetricStore on the main SQL database.
type SQLMetrics struct {
	db    *DB
	mu    sync.Mutex
	cache map[seriesKey]int64
}

// Metrics returns the SQL-backed metric store.
func (d *DB) Metrics() *SQLMetrics {
	return &SQLMetrics{db: d, cache: map[seriesKey]int64{}}
}

func (m *SQLMetrics) seriesID(ctx context.Context, tx execQuerier, k seriesKey) (int64, error) {
	if id, ok := m.cache[k]; ok {
		return id, nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO series(host_id, name, labels) VALUES (?,?,?) ON CONFLICT(host_id, name, labels) DO NOTHING`, k.host, k.name, k.labels); err != nil {
		return 0, err
	}
	var id int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM series WHERE host_id = ? AND name = ? AND labels = ?`, k.host, k.name, k.labels).Scan(&id); err != nil {
		return 0, err
	}
	m.cache[k] = id
	return id, nil
}

// Ingest stores raw samples for a host.
func (m *SQLMetrics) Ingest(ctx context.Context, hostID string, samples []protocol.Sample) error {
	if len(samples) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	tx, err := m.db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	ins, err := tx.PrepareContext(ctx, `INSERT INTO metrics_raw(series_id, ts, value) VALUES (?,?,?) ON CONFLICT(series_id, ts) DO UPDATE SET value = excluded.value`)
	if err != nil {
		return err
	}
	defer ins.Close()
	last := map[int64]protocol.Sample{}
	for _, s := range samples {
		if s.Name == "" || len(s.Name) > 100 || len(s.Labels) > 200 {
			continue
		}
		id, err := m.seriesID(ctx, tx, seriesKey{hostID, s.Name, s.Labels})
		if err != nil {
			return fmt.Errorf("series id: %w", err)
		}
		if _, err := ins.ExecContext(ctx, id, s.TS, s.Value); err != nil {
			return err
		}
		if s.TS >= last[id].TS {
			last[id] = s
		}
	}
	for id, s := range last {
		if _, err := tx.ExecContext(ctx, `UPDATE series SET last_ts = ?, last_val = ? WHERE id = ? AND last_ts <= ?`, s.TS, s.Value, id, s.TS); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		m.cache = map[seriesKey]int64{} // tx rolled back: ids may be invalid
		return err
	}
	return nil
}

// Latest returns the newest value of every series of a host keyed "name{labels}".
func (m *SQLMetrics) Latest(ctx context.Context, hostID string) (map[string]float64, error) {
	rows, err := m.db.sql.QueryContext(ctx, `SELECT name, labels, last_val FROM series WHERE host_id = ? AND last_ts > ?`, hostID, m.db.now().Add(-10*time.Minute).Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]float64{}
	for rows.Next() {
		var n, l string
		var v float64
		if err := rows.Scan(&n, &l, &v); err != nil {
			return nil, err
		}
		out[SeriesKey(n, l)] = v
	}
	return out, rows.Err()
}

// SeriesKey formats "name" or "name{labels}".
func SeriesKey(name, labels string) string {
	if labels == "" {
		return name
	}
	return name + "{" + labels + "}"
}

// AutoResolution picks the storage tier for a time range.
func AutoResolution(from, to, now time.Time) string {
	span := to.Sub(from)
	switch {
	case span <= 6*time.Hour && now.Sub(from) <= 24*time.Hour:
		return "raw"
	case span <= 7*24*time.Hour:
		return "1m"
	}
	return "1h"
}

// Query returns series for a host/name in a time range.
func (m *SQLMetrics) Query(ctx context.Context, q MetricQuery) ([]Series, error) {
	res := q.Resolution
	if res == "" {
		res = AutoResolution(q.From, q.To, m.db.now())
	}
	var table, col string
	switch res {
	case "raw":
		table, col = "metrics_raw", "value"
	case "1m":
		table, col = "metrics_1m", "avg"
	case "1h":
		table, col = "metrics_1h", "avg"
	default:
		return nil, fmt.Errorf("bad resolution %q", res)
	}
	sq := `SELECT s.labels, t.ts, t.` + col + ` FROM series s JOIN ` + table + ` t ON t.series_id = s.id
		WHERE s.host_id = ? AND s.name = ? AND t.ts >= ? AND t.ts <= ?`
	args := []any{q.HostID, q.Name, q.From.Unix(), q.To.Unix()}
	if q.Labels != nil {
		sq += ` AND s.labels = ?`
		args = append(args, *q.Labels)
	}
	sq += ` ORDER BY s.labels, t.ts`
	rows, err := m.db.sql.QueryContext(ctx, sq, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Series
	idx := map[string]int{}
	for rows.Next() {
		var l string
		var p Point
		if err := rows.Scan(&l, &p.TS, &p.Value); err != nil {
			return nil, err
		}
		i, ok := idx[l]
		if !ok {
			i = len(out)
			idx[l] = i
			out = append(out, Series{Name: q.Name, Labels: l})
		}
		out[i].Points = append(out[i].Points, p)
	}
	return out, rows.Err()
}

// Rollup aggregates complete minutes from raw into 1m and complete hours from 1m into 1h.
// Watermarks are kept in settings so each bucket is computed once (idempotent upserts).
func (m *SQLMetrics) Rollup(ctx context.Context, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.rollupTier(ctx, "rollup_1m_wm", "metrics_raw", "metrics_1m", "value", "value", "value", 60, now); err != nil {
		return fmt.Errorf("1m rollup: %w", err)
	}
	if err := m.rollupTier(ctx, "rollup_1h_wm", "metrics_1m", "metrics_1h", "avg", "min", "max", 3600, now); err != nil {
		return fmt.Errorf("1h rollup: %w", err)
	}
	return nil
}

func (m *SQLMetrics) rollupTier(ctx context.Context, wmKey, src, dst, avgCol, minCol, maxCol string, step int64, now time.Time) error {
	end := now.Unix() / step * step // only complete buckets
	wmS, err := m.db.GetSetting(ctx, wmKey)
	if err != nil {
		return err
	}
	var start int64
	if wmS != "" {
		_, _ = fmt.Sscan(wmS, &start)
	} else {
		var minTS *int64
		if err := m.db.sql.QueryRowContext(ctx, `SELECT MIN(ts) FROM `+src).Scan(&minTS); err != nil {
			return err
		}
		if minTS == nil {
			return nil
		}
		start = *minTS / step * step
	}
	if start >= end {
		return nil
	}
	// Late data for already rolled buckets (agent buffer replay) is caught by re-rolling
	// a small overlap window.
	from := start - 10*step
	_, err = m.db.sql.ExecContext(ctx, `INSERT INTO `+dst+`(series_id, ts, avg, min, max)
		SELECT series_id, (ts / ?) * ?, AVG(`+avgCol+`), MIN(`+minCol+`), MAX(`+maxCol+`) FROM `+src+`
		WHERE ts >= ? AND ts < ? GROUP BY series_id, (ts / ?) * ?
		ON CONFLICT(series_id, ts) DO UPDATE SET avg = excluded.avg, min = excluded.min, max = excluded.max`,
		step, step, from, end, step, step)
	if err != nil {
		return err
	}
	return m.db.SetSetting(ctx, wmKey, fmt.Sprint(end))
}

// Prune deletes data older than each tier's retention.
func (m *SQLMetrics) Prune(ctx context.Context, now time.Time, raw, minute, hour time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for table, keep := range map[string]time.Duration{"metrics_raw": raw, "metrics_1m": minute, "metrics_1h": hour} {
		if _, err := m.db.sql.ExecContext(ctx, `DELETE FROM `+table+` WHERE ts < ?`, now.Add(-keep).Unix()); err != nil {
			return fmt.Errorf("prune %s: %w", table, err)
		}
	}
	_, err := m.db.sql.ExecContext(ctx, `DELETE FROM series WHERE last_ts < ?`, now.Add(-hour).Unix())
	if err == nil {
		m.cache = map[seriesKey]int64{}
	}
	return err
}
