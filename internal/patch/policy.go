package patch

import "time"

// Policy modes.
const (
	ModeNotifyOnly   = "notify_only"
	ModeAutoSecurity = "auto_security"
	ModeAutoAll      = "auto_all"
)

// PolicyInput is everything needed to decide whether an automatic run should start.
type PolicyInput struct {
	Mode    string
	Enabled bool
	Window  Window
	Now     time.Time
	// LastRun is the start of the previous automatic run of this policy.
	LastRun time.Time
	// RunningPlan is true while a plan created by this policy is still active.
	RunningPlan bool
	// Candidates is the number of hosts in scope with applicable pending updates.
	Candidates int
}

// ShouldRun reports whether a policy should create and start an automatic plan now.
// Automatic patching only happens inside the maintenance window, at most once per
// window occurrence, never while a previous run is active, and never for notify_only.
func ShouldRun(in PolicyInput) (bool, string) {
	if !in.Enabled {
		return false, "policy disabled"
	}
	if in.Mode != ModeAutoSecurity && in.Mode != ModeAutoAll {
		return false, "notify-only policy"
	}
	open, end := in.Window.Open(in.Now)
	if !open {
		return false, "outside maintenance window"
	}
	if in.RunningPlan {
		return false, "previous run still active"
	}
	if !in.LastRun.IsZero() && in.LastRun.After(end.Add(-in.Window.Duration)) {
		return false, "already ran in this window"
	}
	if in.Candidates == 0 {
		return false, "nothing to patch"
	}
	return true, ""
}
