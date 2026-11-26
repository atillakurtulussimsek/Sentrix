// Package cli holds helpers shared by the Sentrix command-line binaries.
package cli

import (
	"log/slog"
	"os"
	"strings"
)

// Logger builds a text slog logger at the given level.
func Logger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}
