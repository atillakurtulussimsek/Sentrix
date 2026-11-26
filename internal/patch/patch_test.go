package patch

import (
	"testing"
	"time"
)

func mustWindow(t *testing.T, expr string, d time.Duration) Window {
	t.Helper()
	w, err := ParseWindow(expr, d)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestWindowOpen(t *testing.T) {
	ist, _ := time.LoadLocation("Europe/Istanbul")
	w := mustWindow(t, "CRON_TZ=Europe/Istanbul 0 3 * * SUN", 2*time.Hour)
	// Sunday 2026-11-29 03:00 Istanbul
	sun3 := time.Date(2026, 11, 29, 3, 0, 0, 0, ist)
	cases := []struct {
		t    time.Time
		open bool
	}{
		{sun3.Add(-time.Minute), false},
		{sun3, true},
		{sun3.Add(119 * time.Minute), true},
		{sun3.Add(2 * time.Hour), false},
		{sun3.Add(24 * time.Hour), false},        // Monday
		{sun3.UTC().Add(30 * time.Minute), true}, // same instant in UTC
	}
	for _, c := range cases {
		if got, _ := w.Open(c.t); got != c.open {
			t.Errorf("Open(%v) = %v, want %v", c.t, got, c.open)
		}
	}
	if _, end := w.Open(sun3.Add(time.Hour)); !end.Equal(sun3.Add(2 * time.Hour)) {
		t.Errorf("end = %v", end)
	}
	if n := w.Next(sun3.Add(time.Minute)); !n.Equal(sun3.AddDate(0, 0, 7)) {
		t.Errorf("next = %v", n)
	}
	// window spanning midnight
	w2 := mustWindow(t, "30 23 * * *", 90*time.Minute)
	at := time.Date(2026, 1, 2, 0, 30, 0, 0, time.UTC)
	if ok, _ := w2.Open(at); !ok {
		t.Error("midnight-spanning window")
	}
	if _, err := ParseWindow("not cron", time.Hour); err == nil {
		t.Error("invalid cron accepted")
	}
	if _, err := ParseWindow("0 3 * * *", 0); err == nil {
		t.Error("zero duration accepted")
	}
}

func TestShouldRun(t *testing.T) {
	w := mustWindow(t, "0 3 * * *", time.Hour)
	in := time.Date(2026, 3, 1, 3, 10, 0, 0, time.UTC)
	out := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	base := PolicyInput{Mode: ModeAutoSecurity, Enabled: true, Window: w, Candidates: 2}
	cases := []struct {
		name string
		mod  func(*PolicyInput)
		want bool
	}{
		{"inside window", func(p *PolicyInput) { p.Now = in }, true},
		{"outside window does nothing", func(p *PolicyInput) { p.Now = out }, false},
		{"notify only", func(p *PolicyInput) { p.Now = in; p.Mode = ModeNotifyOnly }, false},
		{"disabled", func(p *PolicyInput) { p.Now = in; p.Enabled = false }, false},
		{"running", func(p *PolicyInput) { p.Now = in; p.RunningPlan = true }, false},
		{"already ran this window", func(p *PolicyInput) { p.Now = in; p.LastRun = in.Add(-5 * time.Minute) }, false},
		{"ran yesterday", func(p *PolicyInput) { p.Now = in; p.LastRun = in.Add(-24 * time.Hour) }, true},
		{"nothing to patch", func(p *PolicyInput) { p.Now = in; p.Candidates = 0 }, false},
	}
	for _, c := range cases {
		p := base
		c.mod(&p)
		if got, why := ShouldRun(p); got != c.want {
			t.Errorf("%s: got %v (%s)", c.name, got, why)
		}
	}
}

func TestNextHostsCanary(t *testing.T) {
	hs := []HostState{{"a", 0, "pending"}, {"b", 1, "pending"}, {"c", 2, "pending"}, {"d", 3, "pending"}}
	d := NextHosts(hs, 1, 3)
	if len(d.Start) != 1 || d.Start[0] != "a" {
		t.Fatalf("canary first: %+v", d)
	}
	hs[0].Status = "active"
	if d := NextHosts(hs, 1, 3); len(d.Start) != 0 {
		t.Fatalf("must wait for canary: %+v", d)
	}
	hs[0].Status = "done"
	d = NextHosts(hs, 1, 2)
	if len(d.Start) != 2 || d.Start[0] != "b" || d.Start[1] != "c" {
		t.Fatalf("max parallel 2: %+v", d)
	}
	hs[1].Status, hs[2].Status = "failed", "active"
	if d := NextHosts(hs, 1, 2); !d.Abort || d.Finish || len(d.Start) != 0 {
		t.Fatalf("failure waits for in-flight: %+v", d)
	}
	hs[2].Status = "done"
	if d := NextHosts(hs, 1, 2); !d.Abort || !d.Finish {
		t.Fatalf("abort: %+v", d)
	}
	all := []HostState{{"a", 0, "done"}, {"b", 1, "skipped"}}
	if d := NextHosts(all, 0, 1); !d.Finish || d.Abort {
		t.Fatalf("finish: %+v", d)
	}
}
