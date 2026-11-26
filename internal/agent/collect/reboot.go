package collect

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/vuln/version"
)

// RebootCheck detects whether a reboot is pending.
type RebootCheck struct {
	Root     string // filesystem root, "/" in production
	ProcRoot string
	Run      Runner
}

// Check returns the reboot status.
func (r *RebootCheck) Check(ctx context.Context) protocol.RebootStatus {
	root := r.Root
	if root == "" {
		root = "/"
	}
	var st protocol.RebootStatus
	if b, err := os.ReadFile(procPath(r.ProcRoot, "sys", "kernel", "osrelease")); err == nil {
		st.RunningKernel = strings.TrimSpace(string(b))
	}
	if _, err := os.Stat(filepath.Join(root, "var/run/reboot-required")); err == nil {
		reason := "/var/run/reboot-required present"
		if b, err := os.ReadFile(filepath.Join(root, "var/run/reboot-required.pkgs")); err == nil {
			if pk := strings.Fields(string(b)); len(pk) > 0 {
				reason += " (" + strings.Join(pk, ", ") + ")"
			}
		}
		st.Required = true
		st.Reasons = append(st.Reasons, reason)
	}
	if r.Run != nil {
		if _, err := exec.LookPath("needs-restarting"); err == nil {
			_, err := r.Run(ctx, "needs-restarting", "-r")
			var ee *exec.ExitError
			if errors.As(err, &ee) && ee.ExitCode() == 1 {
				st.Required = true
				st.Reasons = append(st.Reasons, "needs-restarting -r reports reboot required")
			}
		}
	}
	if newest := NewestKernel(root); newest != "" {
		st.NewestKernel = newest
		if st.RunningKernel != "" && newest != st.RunningKernel && version.RPMVerCmp(newest, st.RunningKernel) > 0 {
			st.Required = true
			st.Reasons = append(st.Reasons, "running kernel "+st.RunningKernel+" older than installed "+newest)
		}
	}
	return st
}

// NewestKernel returns the newest kernel release found in /lib/modules (or /boot).
func NewestKernel(root string) string {
	var cands []string
	if ents, err := os.ReadDir(filepath.Join(root, "lib/modules")); err == nil {
		for _, e := range ents {
			// only directories that contain a real kernel image or modules.dep
			if _, err := os.Stat(filepath.Join(root, "lib/modules", e.Name(), "modules.dep")); err == nil {
				cands = append(cands, e.Name())
			}
		}
	}
	if len(cands) == 0 {
		if ents, err := os.ReadDir(filepath.Join(root, "boot")); err == nil {
			for _, e := range ents {
				if v, ok := strings.CutPrefix(e.Name(), "vmlinuz-"); ok && !strings.Contains(v, "rescue") {
					cands = append(cands, v)
				}
			}
		}
	}
	newest := ""
	for _, c := range cands {
		if newest == "" || version.RPMVerCmp(c, newest) > 0 {
			newest = c
		}
	}
	return newest
}
