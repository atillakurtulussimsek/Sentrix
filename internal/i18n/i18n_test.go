package i18n

import (
	"regexp"
	"testing"
)

var verbRe = regexp.MustCompile(`%[-+# 0-9.]*[a-zA-Z%]`)

// TestCatalogParity ensures every language has exactly the same keys and the
// same format verbs, so no screen silently falls back or mis-formats.
func TestCatalogParity(t *testing.T) {
	c := Default()
	langs := c.Languages()
	if langs[0] != DefaultLang {
		t.Fatalf("default language first: got %v", langs)
	}
	ref := c.Keys(FallbackLang)
	for _, l := range langs {
		for _, k := range ref {
			if !c.Has(l, k) {
				t.Errorf("%s: missing key %q", l, k)
				continue
			}
			if a, b := verbRe.FindAllString(c.T(FallbackLang, k), -1), verbRe.FindAllString(c.T(l, k), -1); len(a) != len(b) {
				t.Errorf("%s: key %q has verbs %v, want %v", l, k, b, a)
			}
		}
		for _, k := range c.Keys(l) {
			if !c.Has(FallbackLang, k) {
				t.Errorf("%s: extra key %q not in %s", l, k, FallbackLang)
			}
		}
	}
}

func TestNormalizeAndMatch(t *testing.T) {
	c := Default()
	for in, want := range map[string]string{"tr-TR": "tr", "en_US.UTF-8": "en", "TR": "tr", "de": "", "": ""} {
		if got := c.Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
	if got := c.Match("de-DE,tr;q=0.8,en;q=0.5"); got != "tr" {
		t.Errorf("Match = %q", got)
	}
	if got := c.T("tr", "time.ago", "5 dk"); got != "5 dk önce" {
		t.Errorf("T with args = %q", got)
	}
}
