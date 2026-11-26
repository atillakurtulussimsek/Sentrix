// Package i18n is a minimal message catalog. English is the source language; other
// languages fall back to English for missing keys.
package i18n

import (
	"encoding/json"
	"io/fs"
	"path"
	"strings"
)

// Catalog maps language → key → message.
type Catalog struct {
	msgs map[string]map[string]string
}

// Load reads every <lang>.json in dir of fsys.
func Load(fsys fs.FS, dir string) (*Catalog, error) {
	c := &Catalog{msgs: map[string]map[string]string{}}
	ents, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		b, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		m := map[string]string{}
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		c.msgs[strings.TrimSuffix(e.Name(), ".json")] = m
	}
	return c, nil
}

// T translates key into lang, falling back to English and then the key itself.
func (c *Catalog) T(lang, key string) string {
	if m, ok := c.msgs[lang]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	if v, ok := c.msgs["en"][key]; ok {
		return v
	}
	return key
}

// Languages returns the available language codes.
func (c *Catalog) Languages() []string {
	out := make([]string, 0, len(c.msgs))
	for k := range c.msgs {
		out = append(out, k)
	}
	return out
}

// Match picks the best supported language from an Accept-Language header.
func (c *Catalog) Match(accept string) string {
	for _, part := range strings.Split(accept, ",") {
		tag := strings.ToLower(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]))
		base := strings.SplitN(tag, "-", 2)[0]
		if _, ok := c.msgs[base]; ok {
			return base
		}
	}
	return "en"
}
