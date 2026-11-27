package notify

import (
	"fmt"
	"strings"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/i18n"
)

// RuleConfig is the JSON configuration of an alert rule.
type RuleConfig struct {
	// threshold rules
	Metric string  `json:"metric,omitempty"` // e.g. disk.used_pct
	Labels string  `json:"labels,omitempty"` // exact label set, e.g. "mount=/"; "" = every series
	Op     string  `json:"op,omitempty"`     // > >= < <=
	Value  float64 `json:"value,omitempty"`
	// state rules: agent_offline | failed_units | service_down | reboot_pending
	Condition string `json:"condition,omitempty"`
	// vulnerability rules
	OnlyKEV     bool   `json:"only_kev,omitempty"`
	MinSeverity string `json:"min_severity,omitempty"` // critical|high|medium|low
	// patch rules
	OnlyFailed bool `json:"only_failed,omitempty"`
	// scope (empty = all hosts)
	Group string `json:"group,omitempty"`
}

// Validate checks a configuration for a rule kind.
func (c RuleConfig) Validate(kind string) error {
	switch kind {
	case "threshold":
		if c.Metric == "" {
			return fmt.Errorf("metric required")
		}
		switch c.Op {
		case ">", ">=", "<", "<=":
		default:
			return fmt.Errorf("op must be one of > >= < <=")
		}
	case "state":
		switch c.Condition {
		case "agent_offline", "failed_units", "service_down", "reboot_pending":
		default:
			return fmt.Errorf("unknown state condition %q", c.Condition)
		}
	case "vulnerability", "patch":
	default:
		return fmt.Errorf("unknown rule kind %q", kind)
	}
	return nil
}

// Breaches compares v against the threshold.
func (c RuleConfig) Breaches(v float64) bool {
	switch c.Op {
	case ">":
		return v > c.Value
	case ">=":
		return v >= c.Value
	case "<":
		return v < c.Value
	case "<=":
		return v <= c.Value
	}
	return false
}

// LabelsMatch reports whether a series' labels are selected.
func (c RuleConfig) LabelsMatch(labels string) bool {
	return c.Labels == "" || c.Labels == labels
}

// Translator renders a catalog key (with fmt args) in the caller's language.
type Translator func(key string, args ...any) string

// English translates into English using the embedded catalog.
func English(key string, args ...any) string {
	return i18n.Default().T("en", key, args...)
}

// Describe renders a short human description in English.
func (c RuleConfig) Describe(kind string) string {
	return c.DescribeIn(kind, English)
}

// DescribeIn renders a short human description using t (English when nil).
func (c RuleConfig) DescribeIn(kind string, t Translator) string {
	if t == nil {
		t = English
	}
	switch kind {
	case "threshold":
		s := fmt.Sprintf("%s %s %g", c.Metric, c.Op, c.Value)
		if c.Labels != "" {
			s += " {" + c.Labels + "}"
		}
		return s
	case "state":
		if k := "notify.cond." + c.Condition; t(k) != k {
			return t(k)
		}
		return strings.ReplaceAll(c.Condition, "_", " ")
	case "vulnerability":
		if c.OnlyKEV {
			return t("notify.rule.kev")
		}
		return t("notify.rule.minSeverity", c.MinSeverity)
	case "patch":
		if c.OnlyFailed {
			return t("notify.rule.patchFailed")
		}
		return t("notify.rule.patchFinished")
	}
	return kind
}

// Observation is the evaluated condition for one subject of a rule.
type Observation struct {
	Key     string // dedup key (rule + host + subject)
	HostID  string
	Host    string
	Subject string
	Value   float64
	Message string
}

// Action is what to do after a state transition.
type Action int

// Transition outcomes.
const (
	NoAction Action = iota
	NotifyFiring
	NotifyRepeat
	NotifyResolved
)

// AlertState is the persisted state needed for transitions.
type AlertState struct {
	Exists       bool
	Status       string // pending | firing
	StartedAt    time.Time
	LastNotified time.Time
}

// Transition decides the next alert status given whether the condition is active.
// Pending alerts fire once the condition held for `forDur`. Firing alerts re-notify
// only after `cooldown`; a re-fire of the same key within `cooldown` of the last
// firing notification is suppressed (flap protection). Resolution always notifies
// if the alert had fired.
func Transition(st AlertState, active bool, now time.Time, forDur, cooldown time.Duration, lastFiredNotice time.Time) (status string, act Action) {
	switch {
	case active && !st.Exists:
		if forDur <= 0 {
			if !lastFiredNotice.IsZero() && now.Sub(lastFiredNotice) < cooldown {
				return "firing", NoAction
			}
			return "firing", NotifyFiring
		}
		return "pending", NoAction
	case active && st.Status == "pending":
		if now.Sub(st.StartedAt) >= forDur {
			if !lastFiredNotice.IsZero() && now.Sub(lastFiredNotice) < cooldown {
				return "firing", NoAction
			}
			return "firing", NotifyFiring
		}
		return "pending", NoAction
	case active && st.Status == "firing":
		if cooldown > 0 && now.Sub(st.LastNotified) >= cooldown && !st.LastNotified.IsZero() {
			return "firing", NotifyRepeat
		}
		return "firing", NoAction
	case !active && st.Exists && st.Status == "firing":
		return "resolved", NotifyResolved
	case !active && st.Exists && st.Status == "pending":
		return "", NoAction // drop silently
	}
	return "", NoAction
}
