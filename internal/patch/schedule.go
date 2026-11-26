package patch

// HostState is the scheduling view of one host in a running plan.
type HostState struct {
	ID       string
	Position int
	// Status is one of: pending, active (any in-progress step), done, failed, skipped.
	Status string
}

// Decision is the orchestrator's next move for a running plan.
type Decision struct {
	Start  []string // host IDs to start now
	Finish bool     // plan finished (all hosts terminal)
	Abort  bool     // stop the plan: a failure occurred
	Reason string
}

// NextHosts decides which pending hosts may start. The first `canary` hosts (by
// position) run first, at most maxParallel at a time; the remaining hosts only start
// once every canary host is done. Any failure aborts the rest of the plan (safe
// default: never continue rolling out a patch that broke a host).
func NextHosts(hosts []HostState, canary, maxParallel int) Decision {
	if maxParallel < 1 {
		maxParallel = 1
	}
	active, pending, failed := 0, 0, 0
	for _, h := range hosts {
		switch h.Status {
		case "active":
			active++
		case "pending":
			pending++
		case "failed":
			failed++
		}
	}
	if failed > 0 {
		if active == 0 {
			return Decision{Abort: true, Finish: true, Reason: "a host failed; remaining hosts were not patched"}
		}
		return Decision{Abort: true, Reason: "a host failed; waiting for in-flight hosts"}
	}
	if pending == 0 && active == 0 {
		return Decision{Finish: true}
	}
	canaryDone := true
	for _, h := range hosts {
		if h.Position < canary && h.Status != "done" && h.Status != "skipped" {
			canaryDone = false
		}
	}
	var d Decision
	slots := maxParallel - active
	for _, h := range hosts {
		if slots <= 0 {
			break
		}
		if h.Status != "pending" {
			continue
		}
		if h.Position >= canary && !canaryDone {
			d.Reason = "waiting for canary hosts"
			break
		}
		d.Start = append(d.Start, h.ID)
		slots--
	}
	return d
}
