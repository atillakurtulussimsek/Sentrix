package notify

import (
	"testing"

	"github.com/atillakurtulussimsek/Sentrix/internal/i18n"
)

func TestDescribeIn(t *testing.T) {
	turkish := func(key string, args ...any) string { return i18n.Default().T("tr", key, args...) }
	for _, tc := range []struct {
		kind   string
		cfg    RuleConfig
		en, tr string
	}{
		{"state", RuleConfig{Condition: "agent_offline"}, "agent offline", "ajan çevrimdışı"},
		{"state", RuleConfig{Condition: "new_thing"}, "new thing", "new thing"},
		{"vulnerability", RuleConfig{OnlyKEV: true}, "new known-exploited CVE", "yeni, aktif istismar edilen CVE"},
		{"vulnerability", RuleConfig{MinSeverity: "high"}, "new high+ CVE", "yeni high+ CVE"},
		{"patch", RuleConfig{OnlyFailed: true}, "patch plan failed", "yama planı başarısız"},
		{"threshold", RuleConfig{Metric: "disk.used_pct", Op: ">", Value: 90, Labels: "mount=/"}, "disk.used_pct > 90 {mount=/}", "disk.used_pct > 90 {mount=/}"},
	} {
		if got := tc.cfg.Describe(tc.kind); got != tc.en {
			t.Errorf("Describe(%s) = %q, want %q", tc.kind, got, tc.en)
		}
		if got := tc.cfg.DescribeIn(tc.kind, nil); got != tc.en {
			t.Errorf("DescribeIn(nil) = %q, want %q", got, tc.en)
		}
		if got := tc.cfg.DescribeIn(tc.kind, turkish); got != tc.tr {
			t.Errorf("DescribeIn(tr, %s) = %q, want %q", tc.kind, got, tc.tr)
		}
	}
}
