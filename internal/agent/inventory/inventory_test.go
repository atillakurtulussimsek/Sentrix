package inventory

import (
	"os"
	"testing"
)

func read(t *testing.T, p string) string {
	b, err := os.ReadFile("testdata/" + p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAptSimulate(t *testing.T) {
	u := ParseAptSimulate(read(t, "apt-simulate.txt"))
	if len(u) != 5 {
		t.Fatalf("got %d: %+v", len(u), u)
	}
	want := map[string]struct {
		cur, nw string
		sec     bool
	}{
		"libssl3":                    {"3.0.11-1~deb12u2", "3.0.15-1~deb12u1", true},
		"openssl":                    {"3.0.11-1~deb12u2", "3.0.15-1~deb12u1", true},
		"tzdata":                     {"2024a-0+deb12u1", "2024b-0+deb12u1", false},
		"linux-image-6.1.0-28-amd64": {"", "6.1.119-1", true},
		"libc6":                      {"2.39-0ubuntu8.2", "2.39-0ubuntu8.3", true},
	}
	for _, x := range u {
		w := want[x.Name]
		if x.CurrentVer != w.cur || x.NewVer != w.nw || x.Security != w.sec {
			t.Errorf("%s: %+v", x.Name, x)
		}
	}
}

func TestDpkgQuery(t *testing.T) {
	p := ParseDpkgQuery(read(t, "dpkg-query.txt"))
	if len(p) != 3 || p[0].SourceName != "openssl" || p[2].Version != "1:1.2.13.dfsg-1" || p[1].SourceVer != "5.2.15-2" {
		t.Fatalf("%+v", p)
	}
}

func TestRPM(t *testing.T) {
	p := ParseRPMQuery(read(t, "rpm-qa.txt"))
	if len(p) != 3 {
		t.Fatalf("%+v", p)
	}
	if p[0].Version != "1:3.0.7-24.el9" || p[0].SourceName != "openssl" || p[0].SourceVer != "1:3.0.7-24.el9" {
		t.Fatalf("openssl-libs %+v", p[0])
	}
	if p[1].Version != "5.1.8-9.el9" || p[2].SourceName != "kernel" {
		t.Fatalf("%+v", p)
	}
	u := ParseDnfCheckUpdate(read(t, "dnf-check-update.txt"))
	if len(u) != 3 || u[0].Name != "openssl-libs" || u[0].NewVer != "1:3.0.7-27.el9" {
		t.Fatalf("%+v", u)
	}
	sec := ParseDnfUpdateinfo(read(t, "dnf-updateinfo.txt"))
	if !sec["openssl-libs"] || !sec["curl"] || sec["tzdata"] || len(sec) != 2 {
		t.Fatalf("%v", sec)
	}
	if nevraName("kernel-core-5.14.0-427.42.1.el9_4.x86_64") != "kernel-core" {
		t.Fatal(nevraName("kernel-core-5.14.0-427.42.1.el9_4.x86_64"))
	}
}

func TestAPK(t *testing.T) {
	p, err := ParseAPKInstalled("testdata/apk-installed")
	if err != nil || len(p) != 2 || p[1].SourceName != "openssl" || p[0].Version != "1.2.4_git20230717-r4" {
		t.Fatalf("%+v %v", p, err)
	}
	u := ParseAPKListUpgradable(read(t, "apk-list-u.txt"))
	if len(u) != 2 || u[0].Name != "libcrypto3" || u[0].NewVer != "3.1.7-r1" || u[0].CurrentVer != "3.1.4-r5" || u[1].Name != "busybox-binsh" {
		t.Fatalf("%+v", u)
	}
}

func TestPorts(t *testing.T) {
	ps := ListeningPorts("testdata/proc")
	if len(ps) != 4 {
		t.Fatalf("%+v", ps)
	}
	if ps[0].Port != 22 || ps[0].Address != "0.0.0.0" || ps[1].Port != 53 || ps[1].Proto != "udp" || ps[1].Address != "127.0.0.53" {
		t.Fatalf("%+v", ps)
	}
	if ps[2].Port != 80 || ps[2].Address != "::" || ps[3].Port != 5432 || ps[3].Address != "127.0.0.1" {
		t.Fatalf("%+v", ps)
	}
}

func TestOSRelease(t *testing.T) {
	kv, err := ParseOSRelease("testdata/os-release")
	if err != nil || kv["ID"] != "debian" || kv["VERSION_CODENAME"] != "bookworm" || kv["PRETTY_NAME"] != "Debian GNU/Linux 12 (bookworm)" {
		t.Fatal(kv, err)
	}
}
