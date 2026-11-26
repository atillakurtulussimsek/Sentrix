package main

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/atillakurtulussimsek/Sentrix/internal/agent/executor"
	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

// patched records hosts whose simulated packages were upgraded.
var (
	patchedMu sync.Mutex
	patched   = map[string]bool{}
)

func isPatched(name string) bool {
	patchedMu.Lock()
	defer patchedMu.Unlock()
	return patched[name]
}

func pkgManager(osID string) string {
	switch osID {
	case "debian", "ubuntu":
		return "dpkg"
	case "alpine":
		return "apk"
	}
	return "rpm"
}

// simulated package-manager output for dry runs and real runs.
func fakeRun(h *fakeHost) func(context.Context, string, ...string) ([]byte, error) {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		ups := demoUpdates[h.os.ID]
		if isPatched(h.name) {
			ups = nil
		}
		dry := len(args) > 0 && (args[0] == "-s" || args[0] == "--assumeno") || (len(args) > 1 && args[1] == "-s")
		var b strings.Builder
		switch name {
		case "apt-get":
			if len(args) > 0 && args[0] == "update" {
				return nil, nil
			}
			for _, u := range ups {
				fmt.Fprintf(&b, "Inst %s [%s] (%s %s [amd64])\n", u.Name, u.CurrentVer, u.NewVer, u.Origin)
			}
		case "dnf", "yum":
			if len(args) > 0 && args[0] == "--version" {
				return []byte("4.14.0"), nil
			}
			b.WriteString("Dependencies resolved.\nUpgrading:\n")
			for _, u := range ups {
				fmt.Fprintf(&b, " %-20s x86_64  %-28s baseos  1.2 M\n", u.Name, u.NewVer)
			}
			b.WriteString("\nTransaction Summary\n")
		case "apk":
			if len(args) > 0 && args[0] == "update" {
				return nil, nil
			}
			for i, u := range ups {
				fmt.Fprintf(&b, "(%d/%d) Upgrading %s (%s -> %s)\n", i+1, len(ups), u.Name, u.CurrentVer, u.NewVer)
			}
		}
		if !dry && (name == "apt-get" || name == "dnf" || name == "apk") {
			patchedMu.Lock()
			patched[h.name] = true
			patchedMu.Unlock()
		}
		return []byte(b.String()), nil
	}
}

func newExecutor(h *fakeHost) *executor.Executor {
	return &executor.Executor{AllowPatching: true, PackageManager: pkgManager(h.os.ID), Run: fakeRun(h),
		SendInventory: func(ctx context.Context) error { return h.a.Post(ctx, protocol.PathInventory, demoInventory(h), nil) }}
}
