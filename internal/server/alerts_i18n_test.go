package server

import (
	"context"
	"strings"
	"testing"

	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

func TestNotificationLanguage(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		lang, digest, fleet, test, tag, seed string
	}{
		{"tr", "Sentrix özeti — ", "Filo: ", "Sentrix test bildirimi", "KRİTİK", "Ajan çevrimdışı"},
		{"en", "Sentrix digest — ", "Fleet: ", "Sentrix test notification", "CRITICAL", "Agent offline"},
	} {
		t.Run(tc.lang, func(t *testing.T) {
			s, _ := newTestServer(t)
			s.cfg.Language = tc.lang
			m, err := s.BuildDigest(ctx)
			if err != nil || !strings.HasPrefix(m.Title, tc.digest) || !strings.HasPrefix(m.Body, tc.fleet) || m.Event != "digest" {
				t.Fatalf("digest %+v %v", m, err)
			}
			if tm := s.testNotification(store.Channel{Kind: "webhook", Name: "ops"}); tm.Title != tc.test || !strings.Contains(tm.Body, "“ops”") || tm.Event != "test" {
				t.Fatalf("test message %+v", tm)
			}
			if got := s.sevTag("critical"); got != tc.tag {
				t.Fatalf("sevTag = %q", got)
			}
			old, _ := s.db.ListRules(ctx) // seeded by New in the config default language
			for _, r := range old {
				_ = s.db.DeleteRule(ctx, r.ID)
			}
			if err := s.seedDefaultRules(ctx); err != nil {
				t.Fatal(err)
			}
			rules, _ := s.db.ListRules(ctx)
			found := false
			for _, r := range rules {
				found = found || r.Name == tc.seed
			}
			if !found {
				t.Fatalf("seeded rule %q missing", tc.seed)
			}
		})
	}
}
