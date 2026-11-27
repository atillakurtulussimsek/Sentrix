package cli

import (
	"os"
	"strings"

	"github.com/atillakurtulussimsek/Sentrix/internal/i18n"
)

// LangEnv is the environment variable selecting the CLI/server language.
const LangEnv = "SENTRIX_LANGUAGE"

// ResolveLang picks the CLI language: the --lang flag value, then SENTRIX_LANGUAGE,
// then the configured language, then Turkish. Unsupported values are skipped;
// LANG/LC_ALL are deliberately ignored (Turkish is the primary language).
func ResolveLang(flagVal, configured string) string {
	c := i18n.Default()
	for _, v := range []string{flagVal, os.Getenv(LangEnv), configured} {
		if l := c.Normalize(v); l != "" {
			return l
		}
	}
	return i18n.DefaultLang
}

// SplitLangFlag removes leading global "--lang X" / "--lang=X" (or "-lang") arguments
// and returns the value and the remaining arguments.
func SplitLangFlag(args []string) (lang string, rest []string) {
	for len(args) > 0 {
		a := strings.TrimLeft(args[0], "-")
		switch {
		case !strings.HasPrefix(args[0], "-"):
			return lang, args
		case a == "lang" && len(args) > 1:
			lang, args = args[1], args[2:]
		case strings.HasPrefix(a, "lang="):
			lang, args = strings.TrimPrefix(a, "lang="), args[1:]
		default:
			return lang, args
		}
	}
	return lang, args
}

// Translator returns a translation function bound to lang.
func Translator(lang string) func(key string, args ...any) string {
	c := i18n.Default()
	return func(key string, args ...any) string { return c.T(lang, key, args...) }
}
