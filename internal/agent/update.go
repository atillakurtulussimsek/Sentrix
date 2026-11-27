package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/selfupdate"
	"github.com/atillakurtulussimsek/Sentrix/internal/version"
)

// installUpdate downloads the release pinned by p from the gateway, verifies it
// against the compiled-in release key, the pinned digest and the running version,
// and atomically replaces the agent executable. The running process keeps the old
// file until restartSelf re-executes.
func (a *Agent) installUpdate(ctx context.Context, p protocol.UpdateAgentParams) (string, error) {
	return a.InstallUpdateTo(ctx, p, "")
}

// InstallUpdateTo is installUpdate writing to target instead of the running
// executable when target is not empty (tests and tools).
func (a *Agent) InstallUpdateTo(ctx context.Context, p protocol.UpdateAgentParams, target string) (string, error) {
	if p.Arch != runtime.GOARCH {
		return "", fmt.Errorf("release is for %s, this agent runs on %s", p.Arch, runtime.GOARCH)
	}
	if selfupdate.Compare(p.Version, version.Version) <= 0 {
		return "", fmt.Errorf("refusing to install %s: not newer than the running agent %s", p.Version, version.Version)
	}
	var m selfupdate.Manifest
	if err := a.c.get(ctx, protocol.PathAgentRelease+"/"+p.Arch, &m); err != nil {
		return "", fmt.Errorf("fetch release manifest: %w", err)
	}
	if err := selfupdate.VerifyManifest(m, nil); err != nil {
		return "", err
	}
	if m.Version != p.Version || m.Arch != p.Arch || m.SHA256 != p.SHA256 {
		return "", errors.New("release offered by the server does not match the requested update")
	}
	body, err := a.c.getRaw(ctx, protocol.PathAgentRelease+"/"+p.Arch+"/binary")
	if err != nil {
		return "", fmt.Errorf("download agent binary: %w", err)
	}
	bin, err := selfupdate.VerifyBinary(m, body)
	_ = body.Close()
	if err != nil {
		return "", err
	}
	if !bytes.HasPrefix(bin, []byte("\x7fELF")) && runtime.GOOS == "linux" {
		return "", errors.New("downloaded agent is not a Linux executable")
	}
	exe := target
	if exe == "" {
		if exe, err = executablePath(); err != nil {
			return "", err
		}
	}
	if err := replaceFile(exe, bin); err != nil {
		return "", fmt.Errorf("install %s: %w", exe, err)
	}
	a.log.Info("agent binary updated; restarting", "from", version.Version, "to", m.Version, "path", exe)
	return fmt.Sprintf("updated %s → %s", version.Version, m.Version), nil
}

// SetRestartHook replaces the post-update re-exec (tests and tools).
func (a *Agent) SetRestartHook(fn func()) { a.restartHook = fn }

func executablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// replaceFile writes data next to path and renames it into place atomically.
func replaceFile(path string, data []byte) error {
	tmp := path + ".new"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755) //nolint:gosec // agent binary must be executable
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// restartSelf replaces the process image with the (updated) agent binary, keeping
// the PID, arguments and environment, so it works with or without systemd.
func (a *Agent) restartSelf() {
	if a.restartHook != nil {
		a.restartHook()
		return
	}
	exe, err := executablePath()
	if err != nil {
		a.log.Error("restart after update", "err", err)
		return
	}
	if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil { //nolint:gosec // re-executes the verified agent binary
		a.log.Error("restart after update", "err", err)
	}
}
