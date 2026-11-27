package cli

import (
	"reflect"
	"testing"
)

func TestResolveLang(t *testing.T) {
	t.Setenv(LangEnv, "")
	t.Setenv("LANG", "en_US.UTF-8")
	if got := ResolveLang("", ""); got != "tr" {
		t.Errorf("default = %q, want tr (LANG must be ignored)", got)
	}
	if got := ResolveLang("", "en"); got != "en" {
		t.Errorf("configured = %q", got)
	}
	t.Setenv(LangEnv, "en_US.UTF-8")
	if got := ResolveLang("", "tr"); got != "en" {
		t.Errorf("env over config = %q", got)
	}
	if got := ResolveLang("tr", "en"); got != "tr" {
		t.Errorf("flag over env = %q", got)
	}
	t.Setenv(LangEnv, "de")
	if got := ResolveLang("xx", ""); got != "tr" {
		t.Errorf("unsupported values = %q", got)
	}
}

func TestSplitLangFlag(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		lang string
		rest []string
	}{
		{[]string{"--lang", "en", "hosts"}, "en", []string{"hosts"}},
		{[]string{"-lang=tr", "cve", "list"}, "tr", []string{"cve", "list"}},
		{[]string{"hosts", "--lang", "en"}, "", []string{"hosts", "--lang", "en"}},
		{[]string{"--config", "x"}, "", []string{"--config", "x"}},
	} {
		lang, rest := SplitLangFlag(tc.in)
		if lang != tc.lang || !reflect.DeepEqual(rest, tc.rest) {
			t.Errorf("SplitLangFlag(%v) = %q %v", tc.in, lang, rest)
		}
	}
}
