package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Action is one of a fixed, closed set of operations an agent can perform.
// There is deliberately no action that accepts a command string.
type Action string

// The complete list of agent actions.
const (
	ActionRefreshInventory  Action = "refresh_inventory"
	ActionScan              Action = "scan"
	ActionPatchPackages     Action = "patch_packages"
	ActionPatchSecurityOnly Action = "patch_security_only"
	ActionPatchAll          Action = "patch_all"
	ActionReboot            Action = "reboot"
	ActionRestartService    Action = "restart_service"
	// ActionUpdateAgent replaces the agent binary with a release signed by the
	// Varkhe Digital release key (verified by the agent, see internal/selfupdate).
	ActionUpdateAgent Action = "update_agent"
)

// KnownActions lists every action an agent accepts.
var KnownActions = []Action{
	ActionRefreshInventory, ActionScan, ActionPatchPackages, ActionPatchSecurityOnly,
	ActionPatchAll, ActionReboot, ActionRestartService, ActionUpdateAgent,
}

// Command is an instruction from the server. ID makes delivery idempotent: agents
// never execute the same ID twice.
type Command struct {
	ID       string          `json:"id"`
	Action   Action          `json:"action"`
	Params   json.RawMessage `json:"params,omitempty"`
	DryRun   bool            `json:"dry_run"`
	IssuedAt time.Time       `json:"issued_at"`
}

// PatchPackagesParams selects packages to upgrade.
type PatchPackagesParams struct {
	Packages []string `json:"packages"`
}

// RestartServiceParams names a systemd unit to restart.
type RestartServiceParams struct {
	Name string `json:"name"`
}

// RebootParams controls a reboot.
type RebootParams struct {
	DelaySeconds int `json:"delay_seconds,omitempty"`
}

// UpdateAgentParams pins the release the agent must install. The agent fetches the
// signed manifest and binary from the gateway and refuses anything that does not
// match these values or is not signed by the release key.
type UpdateAgentParams struct {
	Version string `json:"version"`
	Arch    string `json:"arch"`
	SHA256  string `json:"sha256"`
}

// Command result states.
const (
	StatusOK       = "ok"
	StatusFailed   = "failed"
	StatusRejected = "rejected"
)

// CommandResult is the outcome of a command reported by the agent.
type CommandResult struct {
	ID         string          `json:"id"`
	Status     string          `json:"status"`
	Output     string          `json:"output,omitempty"`
	Error      string          `json:"error,omitempty"`
	Changes    []PackageChange `json:"changes,omitempty"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt time.Time       `json:"finished_at"`
	RebootReq  bool            `json:"reboot_required"`
}

// PackageChange is one package transition reported by a dry-run or real patch.
type PackageChange struct {
	Name string `json:"name"`
	From string `json:"from,omitempty"`
	To   string `json:"to"`
}

// CommandsResponse is returned by the long-poll endpoint.
type CommandsResponse struct {
	Commands []Command `json:"commands"`
}

// ResultsRequest posts command results.
type ResultsRequest struct {
	Results []CommandResult `json:"results"`
}

var (
	// Package names: Debian policy, RPM and apk names are all within this set.
	packageNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_\-]{0,127}$`)
	// systemd unit names (optionally with @instance and a type suffix).
	unitNameRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@\-]{0,127}$`)
	commandIDRe = regexp.MustCompile(`^[A-Za-z0-9\-]{1,64}$`)
	// Agent self-update parameters.
	releaseVersionRe = regexp.MustCompile(`^v\d{1,4}\.\d{1,4}\.\d{1,4}$`)
	sha256Re         = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ErrUnknownAction is returned for any action outside KnownActions.
var ErrUnknownAction = errors.New("unknown action")

// ValidPackageName reports whether s is a safe package name.
func ValidPackageName(s string) bool { return packageNameRe.MatchString(s) }

// ValidUnitName reports whether s is a safe systemd unit name.
func ValidUnitName(s string) bool { return unitNameRe.MatchString(s) }

func decodeStrict(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// Validate checks the command against the closed action set and validates parameters
// strictly (unknown fields rejected). Both server and agent call it.
func (c Command) Validate() error {
	if !commandIDRe.MatchString(c.ID) {
		return fmt.Errorf("invalid command id %q", c.ID)
	}
	switch c.Action {
	case ActionRefreshInventory, ActionScan, ActionPatchSecurityOnly, ActionPatchAll:
		var empty struct{}
		if err := decodeStrict(c.Params, &empty); err != nil {
			return fmt.Errorf("%s takes no parameters: %w", c.Action, err)
		}
	case ActionPatchPackages:
		var p PatchPackagesParams
		if err := decodeStrict(c.Params, &p); err != nil {
			return fmt.Errorf("patch_packages params: %w", err)
		}
		if len(p.Packages) == 0 || len(p.Packages) > 500 {
			return errors.New("patch_packages: need 1..500 packages")
		}
		for _, n := range p.Packages {
			if !ValidPackageName(n) {
				return fmt.Errorf("patch_packages: invalid package name %q", n)
			}
		}
	case ActionRestartService:
		var p RestartServiceParams
		if err := decodeStrict(c.Params, &p); err != nil {
			return fmt.Errorf("restart_service params: %w", err)
		}
		if !ValidUnitName(p.Name) {
			return fmt.Errorf("restart_service: invalid unit name %q", p.Name)
		}
	case ActionReboot:
		var p RebootParams
		if err := decodeStrict(c.Params, &p); err != nil {
			return fmt.Errorf("reboot params: %w", err)
		}
		if p.DelaySeconds < 0 || p.DelaySeconds > 3600 {
			return errors.New("reboot: delay out of range")
		}
	case ActionUpdateAgent:
		var p UpdateAgentParams
		if err := decodeStrict(c.Params, &p); err != nil {
			return fmt.Errorf("update_agent params: %w", err)
		}
		if !releaseVersionRe.MatchString(p.Version) || (p.Arch != "amd64" && p.Arch != "arm64") || !sha256Re.MatchString(p.SHA256) {
			return errors.New("update_agent: invalid version, arch or sha256")
		}
	default:
		return fmt.Errorf("%w: %q", ErrUnknownAction, c.Action)
	}
	return nil
}
