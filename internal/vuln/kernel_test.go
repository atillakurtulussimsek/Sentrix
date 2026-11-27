package vuln

import (
	"testing"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/vuln/version"
)

// ubuntuKernelHost mirrors a real Ubuntu 24.04 host: 6.8.0-151 installed by apt but the
// host still runs 6.8.0-142 (no reboot yet); the old image is kept as a fallback.
func ubuntuKernelHost() []protocol.Package {
	src := func(name, ver string) protocol.Package {
		return protocol.Package{Name: name, Version: ver, SourceName: "linux", SourceVer: ver}
	}
	return []protocol.Package{
		src("linux-image-6.8.0-142-generic", "6.8.0-142.142"),
		src("linux-modules-6.8.0-142-generic", "6.8.0-142.142"),
		src("linux-headers-6.8.0-142", "6.8.0-142.142"),
		src("linux-image-6.8.0-151-generic", "6.8.0-151.151"),
		src("linux-modules-6.8.0-151-generic", "6.8.0-151.151"),
		src("linux-headers-6.8.0-151", "6.8.0-151.151"),
		src("linux-libc-dev", "6.8.0-151.151"),
		{Name: "linux-generic", Version: "6.8.0-151.151", SourceName: "linux-meta", SourceVer: "6.8.0-151.151"},
	}
}

var ubuntuKernelIdx = AffectedIndex{"linux": {{VulnID: "UBUNTU-CVE-2026-98432", Package: "linux", Fixed: "6.8.0-149.149", Advisory: "USN-9022-1"}}}

func TestKernelNotRebootedIsVulnerableAndRebootRequired(t *testing.T) {
	fs := Match(version.Dpkg, ubuntuKernelHost(), ubuntuKernelIdx, nil, "6.8.0-142-generic")
	if len(fs) != 1 {
		t.Fatalf("running kernel 6.8.0-142 is vulnerable: want 1 finding, got %+v", fs)
	}
	f := fs[0]
	if f.Installed != "6.8.0-142.142" || !f.RebootRequired {
		t.Fatalf("want installed 6.8.0-142.142 with reboot required, got %+v", f)
	}
	for _, b := range f.Binaries {
		if b == "linux-image-6.8.0-151-generic" {
			t.Fatalf("inactive kernel must not be a matched binary: %v", f.Binaries)
		}
	}
}

func TestKernelAfterRebootOldImageIgnored(t *testing.T) {
	// Rebooted into 6.8.0-151; the 6.8.0-142 packages are still installed as a fallback.
	if fs := Match(version.Dpkg, ubuntuKernelHost(), ubuntuKernelIdx, nil, "6.8.0-151-generic"); len(fs) != 0 {
		t.Fatalf("old, non-running kernel must not produce findings, got %+v", fs)
	}
}

func TestKernelNoFixInstalledNoRebootFlag(t *testing.T) {
	pkgs := ubuntuKernelHost()[:3] // only 6.8.0-142 installed
	fs := Match(version.Dpkg, pkgs, ubuntuKernelIdx, nil, "6.8.0-142-generic")
	if len(fs) != 1 || fs[0].RebootRequired {
		t.Fatalf("want 1 finding without reboot flag, got %+v", fs)
	}
}

func TestKernelUnknownRunningReleaseIsConservative(t *testing.T) {
	// Container inventory: host kernel that matches no installed package, or no kernel at all.
	for _, running := range []string{"", "6.1.0-99-cloud-amd64"} {
		fs := Match(version.Dpkg, ubuntuKernelHost(), ubuntuKernelIdx, nil, running)
		if len(fs) != 1 || fs[0].Installed != "6.8.0-142.142" || fs[0].RebootRequired {
			t.Fatalf("running %q: want unfiltered conservative match, got %+v", running, fs)
		}
	}
}

func TestKernelRPMUsesRunningBuild(t *testing.T) {
	idx := AffectedIndex{"kernel-core": {{VulnID: "CVE-2024-1086", Package: "kernel-core", Fixed: "5.14.0-427.13.1.el9_4"}}}
	pkgs := []protocol.Package{
		{Name: "kernel-core", Version: "5.14.0-362.8.1.el9_3", Arch: "x86_64"},
		{Name: "kernel-core", Version: "5.14.0-427.13.1.el9_4", Arch: "x86_64"},
		{Name: "kernel-headers", Version: "5.14.0-427.13.1.el9_4", Arch: "x86_64"},
	}
	// Still running the old build: vulnerable, fix waits for a reboot.
	fs := Match(version.RPM, pkgs, idx, nil, "5.14.0-362.8.1.el9_3.x86_64")
	if len(fs) != 1 || fs[0].Installed != "5.14.0-362.8.1.el9_3" || !fs[0].RebootRequired {
		t.Fatalf("want old running build vulnerable with reboot flag, got %+v", fs)
	}
	// Rebooted into the fixed build.
	if fs := Match(version.RPM, pkgs, idx, nil, "5.14.0-427.13.1.el9_4.x86_64"); len(fs) != 0 {
		t.Fatalf("fixed running build must not match, got %+v", fs)
	}
}
