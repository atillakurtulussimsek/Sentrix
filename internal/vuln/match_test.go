package vuln

import (
	"testing"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/vuln/version"
)

func TestMatchDebianSourcePackages(t *testing.T) {
	idx := AffectedIndex{
		"openssl": {{VulnID: "CVE-2024-5535", Package: "openssl", Fixed: "3.0.15-1~deb12u1", Advisory: "DSA-5764-1"}},
		"glibc": {
			{VulnID: "CVE-2010-4756", Package: "glibc", DistroSeverity: "unimportant"},
			{VulnID: "CVE-2024-2961", Package: "glibc", Fixed: "2.36-9+deb12u6"},
		},
		"zlib": {{VulnID: "CVE-2023-45853", Package: "zlib", Introduced: "1:1.3", Fixed: "1:1.3.1"}},
	}
	pkgs := []protocol.Package{
		{Name: "libssl3", Version: "3.0.11-1~deb12u2", SourceName: "openssl", SourceVer: "3.0.11-1~deb12u2"},
		{Name: "openssl", Version: "3.0.11-1~deb12u2", SourceName: "openssl", SourceVer: "3.0.11-1~deb12u2"},
		// binNMU: binary version differs from source version; source version must be used
		{Name: "libc6", Version: "2.36-9+deb12u7+b1", SourceName: "glibc", SourceVer: "2.36-9+deb12u7"},
		{Name: "zlib1g", Version: "1:1.2.13.dfsg-1", SourceName: "zlib", SourceVer: "1:1.2.13.dfsg-1"},
	}
	ports := []protocol.ListeningPort{{Proto: "tcp", Address: "0.0.0.0", Port: 22, Process: "sshd"}}
	fs := Match(version.Dpkg, pkgs, idx, ports)
	if len(fs) != 2 {
		t.Fatalf("want 2 findings (openssl fixable, glibc unfixed), got %+v", fs)
	}
	if fs[0].VulnID != "CVE-2010-4756" || fs[0].FixAvailable() || fs[0].DistroSev != "unimportant" {
		t.Fatalf("glibc: %+v", fs[0])
	}
	o := fs[1]
	if o.VulnID != "CVE-2024-5535" || o.Fixed != "3.0.15-1~deb12u1" || o.Installed != "3.0.11-1~deb12u2" || len(o.Binaries) != 2 || o.Advisory != "DSA-5764-1" {
		t.Fatalf("openssl: %+v", o)
	}
	// after upgrade the finding disappears
	for i := range pkgs[:2] {
		pkgs[i].Version, pkgs[i].SourceVer = "3.0.15-1~deb12u1", "3.0.15-1~deb12u1"
	}
	for _, f := range Match(version.Dpkg, pkgs, idx, nil) {
		if f.VulnID == "CVE-2024-5535" {
			t.Fatal("fixed package still reported")
		}
	}
}

func TestMatchRPMAndExposure(t *testing.T) {
	idx := AffectedIndex{
		"openssh-server": {{VulnID: "CVE-2024-6387", Fixed: "8.7p1-38.el9_4.1", Advisory: "RLSA-2024:4312"}},
		"kernel-core":    {{VulnID: "CVE-2024-1086", Fixed: "5.14.0-427.13.1.el9_4"}},
	}
	pkgs := []protocol.Package{
		{Name: "openssh-server", Version: "8.7p1-38.el9"},
		// two kernels installed: the newest decides
		{Name: "kernel-core", Version: "5.14.0-362.8.1.el9_3"},
		{Name: "kernel-core", Version: "5.14.0-427.13.1.el9_4"},
	}
	ports := []protocol.ListeningPort{{Proto: "tcp", Address: "::", Port: 22, Process: "sshd"}, {Proto: "tcp", Address: "127.0.0.1", Port: 25, Process: "master"}}
	fs := Match(version.RPM, pkgs, idx, ports)
	if len(fs) != 1 || fs[0].VulnID != "CVE-2024-6387" || fs[0].Exposed == "" {
		t.Fatalf("%+v", fs)
	}
}

func TestMatchHighestFixWins(t *testing.T) {
	idx := AffectedIndex{"openssl": {
		{VulnID: "CVE-X", Fixed: "3.1.4-r6", Advisory: "A"},
		{VulnID: "CVE-X", Fixed: "3.1.5-r0", Advisory: "B"},
	}}
	fs := Match(version.APK, []protocol.Package{{Name: "libcrypto3", Version: "3.1.4-r5", SourceName: "openssl"}}, idx, nil)
	if len(fs) != 1 || fs[0].Fixed != "3.1.5-r0" || fs[0].Advisory != "A B" {
		t.Fatalf("%+v", fs)
	}
}

func TestRiskScore(t *testing.T) {
	s, comps := Score(RiskInput{CVSS: 8.1, Severity: "high", EPSS: 0.95, EPSSPct: 0.994, KEV: true, FixAvailable: true, Exposed: true})
	if s != 88.5 || len(comps) != 4 {
		t.Fatalf("%v %+v", s, comps)
	}
	low, _ := Score(RiskInput{Severity: "unknown", DistroSev: "unimportant"})
	if low != 10.2 {
		t.Fatalf("low %v", low)
	}
	full, _ := Score(RiskInput{CVSS: 10, EPSSPct: 1, KEV: true, Exposed: true, FixAvailable: true})
	if full != 100 {
		t.Fatalf("cap %v", full)
	}
}

func TestEcosystem(t *testing.T) {
	cases := map[protocol.OSInfo]string{
		{ID: "debian", VersionID: "12"}:      "debian:12",
		{ID: "debian", Codename: "trixie"}:   "debian:13",
		{ID: "ubuntu", VersionID: "24.04"}:   "ubuntu:24.04",
		{ID: "alpine", VersionID: "3.19.1"}:  "alpine:3.19",
		{ID: "rocky", VersionID: "9.4"}:      "rocky:9",
		{ID: "almalinux", VersionID: "8.10"}: "almalinux:8",
	}
	for in, want := range cases {
		if got, _, _ := Ecosystem(in); got != want {
			t.Errorf("%+v → %s", in, got)
		}
	}
	if _, _, ok := Ecosystem(protocol.OSInfo{ID: "fedora", VersionID: "40"}); ok {
		t.Error("fedora has no feed")
	}
}
