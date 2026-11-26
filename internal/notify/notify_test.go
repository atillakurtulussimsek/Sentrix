package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTransition(t *testing.T) {
	t0 := time.Unix(1000, 0)
	cool := time.Hour
	st, act := Transition(AlertState{}, true, t0, 5*time.Minute, cool, time.Time{})
	if st != "pending" || act != NoAction {
		t.Fatal(st, act)
	}
	st, act = Transition(AlertState{Exists: true, Status: "pending", StartedAt: t0}, true, t0.Add(4*time.Minute), 5*time.Minute, cool, time.Time{})
	if st != "pending" || act != NoAction {
		t.Fatal("fired too early")
	}
	st, act = Transition(AlertState{Exists: true, Status: "pending", StartedAt: t0}, true, t0.Add(5*time.Minute), 5*time.Minute, cool, time.Time{})
	if st != "firing" || act != NotifyFiring {
		t.Fatal(st, act)
	}
	fired := t0.Add(5 * time.Minute)
	_, act = Transition(AlertState{Exists: true, Status: "firing", LastNotified: fired}, true, fired.Add(30*time.Minute), 5*time.Minute, cool, fired)
	if act != NoAction {
		t.Fatal("repeated within cooldown")
	}
	_, act = Transition(AlertState{Exists: true, Status: "firing", LastNotified: fired}, true, fired.Add(61*time.Minute), 5*time.Minute, cool, fired)
	if act != NotifyRepeat {
		t.Fatal("no repeat after cooldown")
	}
	st, act = Transition(AlertState{Exists: true, Status: "firing", LastNotified: fired}, false, fired.Add(10*time.Minute), 5*time.Minute, cool, fired)
	if st != "resolved" || act != NotifyResolved {
		t.Fatal(st, act)
	}
	// flapping: fires again within cooldown of the last firing notification → silent
	st, act = Transition(AlertState{Exists: true, Status: "pending", StartedAt: fired.Add(11 * time.Minute)}, true, fired.Add(20*time.Minute), 5*time.Minute, cool, fired)
	if st != "firing" || act != NoAction {
		t.Fatal("flap not suppressed", st, act)
	}
	if st, act := Transition(AlertState{Exists: true, Status: "pending"}, false, t0, time.Minute, cool, time.Time{}); st != "" || act != NoAction {
		t.Fatal("pending should be dropped")
	}
}

func TestRuleConfig(t *testing.T) {
	c := RuleConfig{Metric: "disk.used_pct", Op: ">", Value: 90, Labels: "mount=/"}
	if err := c.Validate("threshold"); err != nil {
		t.Fatal(err)
	}
	if !c.Breaches(90.5) || c.Breaches(90) || !c.LabelsMatch("mount=/") || c.LabelsMatch("mount=/var") {
		t.Fatal("threshold")
	}
	if (RuleConfig{Condition: "nope"}).Validate("state") == nil || (RuleConfig{Metric: "x", Op: "=="}).Validate("threshold") == nil {
		t.Fatal("validation")
	}
}

func TestSenders(t *testing.T) {
	var got []struct {
		path string
		hdr  http.Header
		body string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, struct {
			path string
			hdr  http.Header
			body string
		}{r.URL.Path, r.Header, string(b)})
	}))
	defer srv.Close()
	s := NewSender()
	s.TelegramAPI = srv.URL
	m := Message{Event: "firing", Severity: "critical", Title: "Disk 95% on web-1", Body: "mount=/", Time: time.Now()}
	ctx := context.Background()
	cases := []struct {
		kind string
		cfg  Config
	}{
		{"webhook", Config{URL: srv.URL + "/hook", Secret: "s3"}},
		{"slack", Config{URL: srv.URL + "/slack"}},
		{"discord", Config{URL: srv.URL + "/discord"}},
		{"telegram", Config{Token: "123:abc", ChatID: "42"}},
		{"ntfy", Config{URL: srv.URL, Topic: "ops"}},
	}
	for _, c := range cases {
		if err := s.Send(ctx, c.kind, c.cfg, m); err != nil {
			t.Fatalf("%s: %v", c.kind, err)
		}
	}
	if len(got) != 5 {
		t.Fatalf("requests: %d", len(got))
	}
	var wh Message
	_ = json.Unmarshal([]byte(got[0].body), &wh)
	if wh.Title != m.Title || !strings.HasPrefix(got[0].hdr.Get("X-Sentrix-Signature"), "sha256=") {
		t.Fatalf("webhook %+v", got[0])
	}
	if got[3].path != "/bot123:abc/sendMessage" || !strings.Contains(got[3].body, `"chat_id":"42"`) {
		t.Fatalf("telegram %+v", got[3])
	}
	if got[4].path != "/ops" || got[4].hdr.Get("Priority") != "5" || got[4].body != "mount=/" {
		t.Fatalf("ntfy %+v", got[4])
	}
	// errors must not leak the telegram token in the URL
	s.TelegramAPI = "http://127.0.0.1:1"
	err := s.Send(ctx, "telegram", Config{Token: "999:SECRET", ChatID: "1"}, m)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("token leaked or no error: %v", err)
	}
}
