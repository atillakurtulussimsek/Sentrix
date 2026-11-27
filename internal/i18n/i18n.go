// Package i18n is a minimal message catalog. Turkish is the default language and
// English the fallback for missing keys. Catalogs live in web/i18n/<lang>/*.json;
// all files of a language are merged.
package i18n

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/atillakurtulussimsek/Sentrix/web"
)

// DefaultLang is the product's primary language.
const DefaultLang = "tr"

// FallbackLang is used for keys missing in the requested language.
const FallbackLang = "en"

// displayNames are the language names shown in pickers (in their own language).
var displayNames = map[string]string{"tr": "Türkçe", "en": "English"}

// Catalog maps language → key → message.
type Catalog struct {
	msgs map[string]map[string]string
}

// Load reads every <lang>/*.json (and legacy <lang>.json) under dir of fsys.
func Load(fsys fs.FS, dir string) (*Catalog, error) {
	c := &Catalog{msgs: map[string]map[string]string{}}
	ents, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if e.IsDir() {
			files, err := fs.Glob(fsys, path.Join(dir, e.Name(), "*.json"))
			if err != nil {
				return nil, err
			}
			for _, f := range files {
				if err := c.merge(fsys, f, e.Name()); err != nil {
					return nil, err
				}
			}
			continue
		}
		if strings.HasSuffix(e.Name(), ".json") {
			if err := c.merge(fsys, path.Join(dir, e.Name()), strings.TrimSuffix(e.Name(), ".json")); err != nil {
				return nil, err
			}
		}
	}
	return c, nil
}

func (c *Catalog) merge(fsys fs.FS, file, lang string) error {
	b, err := fs.ReadFile(fsys, file)
	if err != nil {
		return err
	}
	m := map[string]string{}
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	if c.msgs[lang] == nil {
		c.msgs[lang] = map[string]string{}
	}
	for k, v := range m {
		if _, dup := c.msgs[lang][k]; dup {
			return fmt.Errorf("%s: duplicate key %q", file, k)
		}
		c.msgs[lang][k] = v
	}
	return nil
}

var (
	defaultOnce sync.Once
	defaultCat  *Catalog
)

// Default returns the catalog embedded in the binary.
func Default() *Catalog {
	defaultOnce.Do(func() {
		c, err := Load(web.I18n, "i18n")
		if err != nil {
			panic(fmt.Sprintf("embedded i18n catalog: %v", err)) // build-time invariant, covered by tests
		}
		defaultCat = c
	})
	return defaultCat
}

// T translates key into lang, falling back to English and then the key itself.
// With args, the message is used as a fmt format string.
func (c *Catalog) T(lang, key string, args ...any) string {
	msg, ok := c.msgs[lang][key]
	if !ok {
		if msg, ok = c.msgs[FallbackLang][key]; !ok {
			msg = key
		}
	}
	if len(args) > 0 {
		return fmt.Sprintf(msg, args...)
	}
	return msg
}

// Has reports whether key exists in lang.
func (c *Catalog) Has(lang, key string) bool {
	_, ok := c.msgs[lang][key]
	return ok
}

// Keys returns the sorted keys of lang.
func (c *Catalog) Keys(lang string) []string {
	out := make([]string, 0, len(c.msgs[lang]))
	for k := range c.msgs[lang] {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Languages returns the available language codes, default language first.
func (c *Catalog) Languages() []string {
	out := make([]string, 0, len(c.msgs))
	for k := range c.msgs {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i] == DefaultLang || out[j] == DefaultLang {
			return out[i] == DefaultLang
		}
		return out[i] < out[j]
	})
	return out
}

// Supported reports whether lang has a catalog.
func (c *Catalog) Supported(lang string) bool {
	_, ok := c.msgs[lang]
	return ok
}

// Normalize maps a tag such as "tr-TR" or "en_US.UTF-8" to a supported code, or "".
func (c *Catalog) Normalize(tag string) string {
	tag = strings.ToLower(strings.TrimSpace(tag))
	if i := strings.IndexAny(tag, "-_.;@"); i >= 0 {
		tag = tag[:i]
	}
	if c.Supported(tag) {
		return tag
	}
	return ""
}

// Match picks the best supported language from an Accept-Language header, or "".
func (c *Catalog) Match(accept string) string {
	for _, part := range strings.Split(accept, ",") {
		if l := c.Normalize(strings.SplitN(part, ";", 2)[0]); l != "" {
			return l
		}
	}
	return ""
}

// DisplayName returns the language's own name (e.g. "Türkçe").
func DisplayName(lang string) string {
	if n, ok := displayNames[lang]; ok {
		return n
	}
	return lang
}

// Option is a language choice for pickers.
type Option struct{ Code, Name string }

// Options returns the supported languages as picker options.
func (c *Catalog) Options() []Option {
	var out []Option
	for _, l := range c.Languages() {
		out = append(out, Option{Code: l, Name: DisplayName(l)})
	}
	return out
}
