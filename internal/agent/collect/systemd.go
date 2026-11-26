package collect

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

// Runner executes a fixed program with fixed arguments (replaceable in tests).
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// ExecRunner runs a local program with a timeout. Arguments are never passed through a shell.
func ExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	return cmd.Output()
}

// FailedUnits lists failed systemd units.
func FailedUnits(ctx context.Context, run Runner) []string {
	out, err := run(ctx, "systemctl", "list-units", "--failed", "--no-legend", "--plain", "--no-pager")
	if err != nil {
		return nil
	}
	return ParseFailedUnits(string(out))
}

// ParseFailedUnits parses `systemctl list-units --failed --plain --no-legend`.
func ParseFailedUnits(s string) []string {
	var units []string
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(strings.TrimLeft(l, "●* "))
		if len(f) > 0 && strings.Contains(f[0], ".") {
			units = append(units, f[0])
		}
	}
	return units
}

// ServiceStates returns active/sub state of watched units.
func ServiceStates(ctx context.Context, run Runner, units []string) []protocol.ServiceStatus {
	var out []protocol.ServiceStatus
	for _, u := range units {
		if !protocol.ValidUnitName(u) {
			continue
		}
		b, err := run(ctx, "systemctl", "show", "--no-pager", "-p", "ActiveState,SubState", "--", u)
		st := protocol.ServiceStatus{Name: u, ActiveState: "unknown"}
		if err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				k, v, _ := strings.Cut(l, "=")
				switch k {
				case "ActiveState":
					st.ActiveState = v
				case "SubState":
					st.SubState = v
				}
			}
		}
		out = append(out, st)
	}
	return out
}
