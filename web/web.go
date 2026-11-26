// Package web embeds the Sentrix UI templates, static assets and message catalogs.
package web

import "embed"

// Templates holds the HTML templates.
//
//go:embed templates/*.html
var Templates embed.FS

// Static holds CSS, JS and vendored libraries.
//
//go:embed static
var Static embed.FS

// I18n holds message catalogs (one JSON file per language).
//
//go:embed i18n/*.json
var I18n embed.FS
