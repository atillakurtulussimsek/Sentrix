package store

import (
	"context"
	"testing"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

func testDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func addHost(t *testing.T, db *DB, id string) {
	t.Helper()
	if _, err := db.sql.Exec(`INSERT INTO hosts(id, hostname, created_at) VALUES (?, ?, 0)`, id, id); err != nil {
		t.Fatal(err)
	}
}

func TestMetricsIngestRollupPrune(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	addHost(t, db, "h1")
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	db.SetClock(func() time.Time { return base.Add(3 * time.Hour) })
	m := db.Metrics()
	var samples []protocol.Sample
	// 2 hours of 10 s samples: value = minute index within hour
	for ts := base; ts.Before(base.Add(2 * time.Hour)); ts = ts.Add(10 * time.Second) {
		samples = append(samples, protocol.Sample{TS: ts.Unix(), Name: "cpu.usage", Value: float64(ts.Minute())})
		samples = append(samples, protocol.Sample{TS: ts.Unix(), Name: "disk.used_pct", Labels: "mount=/", Value: 50})
	}
	if err := m.Ingest(ctx, "h1", samples); err != nil {
		t.Fatal(err)
	}
	// re-ingest (buffer replay) is idempotent
	if err := m.Ingest(ctx, "h1", samples[:10]); err != nil {
		t.Fatal(err)
	}
	if err := m.Rollup(ctx, base.Add(2*time.Hour+30*time.Second)); err != nil {
		t.Fatal(err)
	}
	ser, err := m.Query(ctx, MetricQuery{HostID: "h1", Name: "cpu.usage", From: base, To: base.Add(2 * time.Hour), Resolution: "1m"})
	if err != nil || len(ser) != 1 || len(ser[0].Points) != 120 {
		t.Fatalf("1m: %v %v", err, ser)
	}
	if p := ser[0].Points[5]; p.TS != base.Add(5*time.Minute).Unix() || p.Value != 5 {
		t.Fatalf("1m point %+v", p)
	}
	hs, _ := m.Query(ctx, MetricQuery{HostID: "h1", Name: "cpu.usage", From: base, To: base.Add(2 * time.Hour), Resolution: "1h"})
	if len(hs) != 1 || len(hs[0].Points) != 2 || hs[0].Points[0].Value != 29.5 {
		t.Fatalf("1h: %+v", hs)
	}
	db.SetClock(func() time.Time { return base.Add(2*time.Hour + time.Minute) })
	lat, _ := m.Latest(ctx, "h1")
	if lat["disk.used_pct{mount=/}"] != 50 || lat["cpu.usage"] != 59 {
		t.Fatalf("latest %v", lat)
	}
	// second rollup is a no-op on watermark
	if err := m.Rollup(ctx, base.Add(2*time.Hour+40*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := m.Prune(ctx, base.Add(2*time.Hour), time.Hour, 24*time.Hour, 90*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	raw, _ := m.Query(ctx, MetricQuery{HostID: "h1", Name: "cpu.usage", From: base, To: base.Add(2 * time.Hour), Resolution: "raw"})
	if raw[0].Points[0].TS < base.Add(time.Hour).Unix() {
		t.Fatal("raw not pruned")
	}
}

func TestAutoResolution(t *testing.T) {
	now := time.Now()
	if AutoResolution(now.Add(-time.Hour), now, now) != "raw" || AutoResolution(now.Add(-48*time.Hour), now, now) != "1m" || AutoResolution(now.Add(-30*24*time.Hour), now, now) != "1h" {
		t.Fatal("resolution")
	}
}
