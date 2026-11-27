package executor

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

func pkgCmd(id string, action protocol.Action, params string, dry bool) protocol.Command {
	return protocol.Command{ID: id, Action: action, Params: json.RawMessage(params), DryRun: dry}
}

func TestPackageManagementDisabledByDefault(t *testing.T) {
	e, fr := newExec("dpkg") // AllowPatching only
	for _, dry := range []bool{true, false} {
		r := e.Execute(context.Background(), pkgCmd("i", protocol.ActionInstallPackages, `{"packages":["htop"]}`, dry))
		if r.Status != protocol.StatusRejected || !strings.Contains(r.Error, "allow_package_management") {
			t.Fatalf("dry=%v: %+v", dry, r)
		}
	}
	if len(fr.calls) != 0 {
		t.Fatalf("programs ran: %+v", fr.calls)
	}
}

func TestInstallAptPreviewThenApply(t *testing.T) {
	e, fr := newExec("dpkg")
	e.AllowPackageManagement = true
	fr.out["apt-get -s"] = "Inst libncursesw6 [6.4-1] (6.4-2 Ubuntu:24.04/noble [amd64])\nInst htop (3.3.0-4 Ubuntu:24.04/noble [amd64])\n"
	r := e.Execute(context.Background(), pkgCmd("a", protocol.ActionInstallPackages, `{"packages":["htop"]}`, true))
	if r.Status != protocol.StatusOK || len(r.Changes) != 2 || r.Changes[1].Name != "htop" || r.Changes[1].To != "3.3.0-4" {
		t.Fatalf("%+v", r)
	}
	for _, c := range fr.calls {
		if c.name == "apt-get" && c.args[0] == "install" {
			t.Fatal("dry run installed for real")
		}
	}
	fr.calls = nil
	r = e.Execute(context.Background(), pkgCmd("b", protocol.ActionInstallPackages, `{"packages":["htop"]}`, false))
	if r.Status != protocol.StatusOK {
		t.Fatalf("%+v", r)
	}
	last := fr.calls[len(fr.calls)-1]
	if last.name != "apt-get" || last.args[0] != "install" || last.args[len(last.args)-1] != "htop" {
		t.Fatalf("install argv: %+v", last)
	}
}

func TestRemoveAptPurgeAndProtectedDependency(t *testing.T) {
	e, fr := newExec("dpkg")
	e.AllowPackageManagement = true
	fr.out["apt-get -s"] = "Purg nano [7.2-1ubuntu0.1]\n"
	r := e.Execute(context.Background(), pkgCmd("p", protocol.ActionRemovePackages, `{"packages":["nano"],"purge":true}`, false))
	if r.Status != protocol.StatusOK || len(r.Changes) != 1 || r.Changes[0].From != "7.2-1ubuntu0.1" || r.Changes[0].To != "" {
		t.Fatalf("%+v", r)
	}
	if last := fr.calls[len(fr.calls)-1]; last.args[0] != "purge" {
		t.Fatalf("want purge, got %v", last.args)
	}

	// Removing a library that openssh-server depends on would take ssh with it: refused.
	fr.calls = nil
	fr.out["apt-get -s"] = "Remv openssh-server [1:9.6p1-3ubuntu13]\nRemv libwrap0 [7.6.q-33]\n"
	r = e.Execute(context.Background(), pkgCmd("q", protocol.ActionRemovePackages, `{"packages":["libwrap0"]}`, false))
	if r.Status != protocol.StatusFailed || !strings.Contains(r.Error, "openssh-server") {
		t.Fatalf("%+v", r)
	}
	for _, c := range fr.calls {
		if c.name == "apt-get" && c.args[0] == "remove" {
			t.Fatal("protected removal executed")
		}
	}
}

func TestRemoveNotInstalled(t *testing.T) {
	e, fr := newExec("dpkg")
	e.AllowPackageManagement = true
	fr.out["apt-get -s"] = "Package 'nano' is not installed, so not removed\n"
	r := e.Execute(context.Background(), pkgCmd("n", protocol.ActionRemovePackages, `{"packages":["nano"]}`, true))
	if r.Status != protocol.StatusFailed || !strings.Contains(r.Error, "not installed: nano") {
		t.Fatalf("%+v", r)
	}
}

func TestProtectedPackagesRejectedBeforeExecution(t *testing.T) {
	e, fr := newExec("dpkg")
	e.AllowPackageManagement = true
	for _, n := range []string{"sentrix-agent", "openssh-server", "linux-image-6.8.0-151-generic", "systemd", "kernel-core", "libc6"} {
		r := e.Execute(context.Background(), pkgCmd("x", protocol.ActionRemovePackages, `{"packages":["`+n+`"]}`, true))
		if r.Status != protocol.StatusRejected {
			t.Errorf("%s: %+v", n, r)
		}
	}
	if len(fr.calls) != 0 {
		t.Fatalf("programs ran: %+v", fr.calls)
	}
}

func TestDnfAndApkRemovalParsing(t *testing.T) {
	dnf := `Dependencies resolved.
================================================================================
 Package           Arch       Version              Repository            Size
================================================================================
Removing:
 nano              x86_64     5.6.1-5.el9          @baseos              2.7 M
Removing unused dependencies:
 libfoo            noarch     1.0-1.el9            @appstream            10 k

Transaction Summary
================================================================================
Remove  2 Packages
Operation aborted.`
	ch := ParseDnfTransaction(dnf)
	if len(ch) != 2 || ch[0].Name != "nano" || ch[0].From != "5.6.1-5.el9" || ch[0].To != "" {
		t.Fatalf("%+v", ch)
	}
	ac := ParseAPKUpgrade("(1/1) Purging nano (7.2-r1)\nOK: 9 MiB in 19 packages")
	if len(ac) != 1 || ac[0].Name != "nano" || ac[0].From != "7.2-r1" || ac[0].To != "" {
		t.Fatalf("%+v", ac)
	}

	e, fr := newExec("rpm")
	e.AllowPackageManagement = true
	fr.out["dnf --assumeno"] = dnf
	r := e.Execute(context.Background(), pkgCmd("d", protocol.ActionRemovePackages, `{"packages":["nano"]}`, true))
	if r.Status != protocol.StatusOK || len(r.Changes) != 2 {
		t.Fatalf("%+v", r)
	}
}
