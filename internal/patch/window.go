// Package patch contains the pure decision logic of patch orchestration: maintenance
// windows, canary/parallelism scheduling and policy evaluation. Side effects (commands,
// storage) live in the server package.
package patch

import (
	"fmt"
	"time"

	"github.com/robfig/cron/v3"
)

// Window is a recurring maintenance window: it opens at each time matched by a cron
// expression and stays open for Duration. The expression may carry a time zone prefix
// ("CRON_TZ=Europe/Istanbul 0 3 * * SUN").
type Window struct {
	Cron     string
	Duration time.Duration
	sched    cron.Schedule
}

var parser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

// ParseWindow validates a window definition.
func ParseWindow(expr string, d time.Duration) (Window, error) {
	if expr == "" {
		return Window{}, fmt.Errorf("empty maintenance window")
	}
	if d <= 0 || d > 7*24*time.Hour {
		return Window{}, fmt.Errorf("window duration must be between 1 minute and 7 days")
	}
	s, err := parser.Parse(expr)
	if err != nil {
		return Window{}, fmt.Errorf("invalid cron expression %q: %w", expr, err)
	}
	return Window{Cron: expr, Duration: d, sched: s}, nil
}

// Open reports whether t falls inside an occurrence of the window, and when that
// occurrence closes.
func (w Window) Open(t time.Time) (bool, time.Time) {
	if w.sched == nil {
		return false, time.Time{}
	}
	// The latest start that could still cover t is at most Duration before t.
	start := w.sched.Next(t.Add(-w.Duration - time.Second))
	if !start.After(t) {
		end := start.Add(w.Duration)
		if t.Before(end) {
			return true, end
		}
	}
	return false, time.Time{}
}

// Next returns the next opening after t.
func (w Window) Next(t time.Time) time.Time {
	if w.sched == nil {
		return time.Time{}
	}
	return w.sched.Next(t)
}
