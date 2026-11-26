package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/notify"
	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

type webhookSink struct {
	mu   sync.Mutex
	msgs []notify.Message
}

func (w *webhookSink) handler(rw http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	var m notify.Message
	_ = json.Unmarshal(b, &m)
	w.mu.Lock()
	w.msgs = append(w.msgs, m)
	w.mu.Unlock()
}

func (w *webhookSink) events() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for _, m := range w.msgs {
		out = append(out, m.Event)
	}
	return out
}

func TestDiskThresholdAlertLifecycle(t *testing.T) {
	ctx := context.Background()
	s, gw := newTestServer(t)
	sink := &webhookSink{}
	recv := httptest.NewServer(http.HandlerFunc(sink.handler))
	defer recv.Close()

	cfg, _ := json.Marshal(notify.Config{URL: recv.URL})
	ch, err := s.db.SaveChannel(ctx, store.Channel{Name: "test hook", Kind: "webhook", Config: string(cfg), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	// only our rule: disable the defaults
	rules, _ := s.db.ListRules(ctx)
	for _, r := range rules {
		r.Enabled = false
		_, _ = s.db.SaveRule(ctx, r)
	}
	rc, _ := json.Marshal(notify.RuleConfig{Metric: "disk.used_pct", Labels: "mount=/data", Op: ">", Value: 90})
	_, err = s.db.SaveRule(ctx, store.Rule{Name: "Test disk", Kind: "threshold", Config: string(rc), Severity: "warning",
		Channels: []string{ch.ID}, For: 5 * time.Minute, Cooldown: time.Hour, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	h := newSimHost(t, s, gw.URL, "files-1")
	clock := time.Now()
	setClock := func(t time.Time) {
		clock = t
		s.now = func() time.Time { return clock }
		s.db.SetClock(s.now)
	}
	disk := func(v float64) {
		t.Helper()
		_ = s.db.MarkSeen(ctx, h.a.ID())
		if err := s.mets.Ingest(ctx, h.a.ID(), []protocol.Sample{{TS: clock.Unix(), Name: "disk.used_pct", Labels: "mount=/data", Value: v}}); err != nil {
			t.Fatal(err)
		}
		if err := s.EvaluateAlerts(ctx); err != nil {
			t.Fatal(err)
		}
	}
	t0 := time.Now()
	setClock(t0)
	disk(95) // pending
	if len(sink.events()) != 0 {
		t.Fatal("notified while pending")
	}
	for m := 1; m <= 4; m++ {
		setClock(t0.Add(time.Duration(m) * time.Minute))
		disk(96)
	}
	if len(sink.events()) != 0 {
		t.Fatal("notified before 'for' elapsed")
	}
	setClock(t0.Add(5 * time.Minute))
	disk(97)                   // fires
	for m := 6; m <= 20; m++ { // still breaching within cooldown
		setClock(t0.Add(time.Duration(m) * time.Minute))
		disk(97)
	}
	if ev := sink.events(); len(ev) != 1 || ev[0] != "firing" {
		t.Fatalf("want exactly one firing notification, got %v", ev)
	}
	setClock(t0.Add(21 * time.Minute))
	disk(40) // resolved
	if ev := sink.events(); len(ev) != 2 || ev[1] != "resolved" {
		t.Fatalf("want resolve notification, got %v", ev)
	}
	// flap within cooldown: fires again silently
	for m := 22; m <= 28; m++ {
		setClock(t0.Add(time.Duration(m) * time.Minute))
		disk(99)
	}
	if ev := sink.events(); len(ev) != 2 {
		t.Fatalf("flap re-notified within cooldown: %v", ev)
	}
	sink.mu.Lock()
	first := sink.msgs[0]
	sink.mu.Unlock()
	if first.Host != "files-1" || first.Value != 97 || first.Severity != "warning" {
		t.Fatalf("payload %+v", first)
	}
	logs, _ := s.db.ListNotifications(ctx, 10)
	if len(logs) != 2 || logs[0].Status != "sent" {
		t.Fatalf("notification log %+v", logs)
	}
}

func TestDigest(t *testing.T) {
	ctx := context.Background()
	s, gw := newTestServer(t)
	_ = newSimHost(t, s, gw.URL, "web-9")
	m, err := s.BuildDigest(ctx)
	if err != nil || m.Event != "digest" || m.Body == "" {
		t.Fatalf("%+v %v", m, err)
	}
}
