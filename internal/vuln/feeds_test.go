package vuln

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const fixtures = "../../test/fixtures/feeds/"

type memSink struct {
	aff  []Affected
	info map[string]Info
}

func (m *memSink) Affected(a Affected) error { m.aff = append(m.aff, a); return nil }
func (m *memSink) Info(i Info) error {
	if m.info == nil {
		m.info = map[string]Info{}
	}
	m.info[i.ID] = i
	return nil
}

func (m *memSink) find(eco, pkg, id string) *Affected {
	for i := range m.aff {
		a := &m.aff[i]
		if a.Ecosystem == eco && a.Package == pkg && a.VulnID == id {
			return a
		}
	}
	return nil
}

func TestDebianTrackerGolden(t *testing.T) {
	f, err := os.Open(fixtures + "debian-tracker.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sink := &memSink{}
	n, err := ParseDebianTracker(f, map[string]bool{"12": true}, sink)
	if err != nil {
		t.Fatal(err)
	}
	// openssl CVE-2024-5535 (fixed), glibc CVE-2010-4756 (open), glibc CVE-2024-2961 (fixed).
	// CVE-2023-0464 fixed_version 0 (not affected), TEMP id and bullseye/sid are skipped.
	if n != 3 || len(sink.aff) != 3 {
		t.Fatalf("n=%d %+v", n, sink.aff)
	}
	if a := sink.find("debian:12", "openssl", "CVE-2024-5535"); a == nil || a.Fixed != "3.0.15-1~deb12u1" {
		t.Fatalf("openssl: %+v", a)
	}
	if a := sink.find("debian:12", "glibc", "CVE-2010-4756"); a == nil || a.Fixed != "" || a.DistroSeverity != "unimportant" {
		t.Fatalf("glibc open: %+v", a)
	}
	if sink.info["CVE-2024-2961"].Summary == "" {
		t.Fatal("missing description")
	}
}

func TestOSVGolden(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files, _ := filepath.Glob(fixtures + "osv/*.json")
	for _, p := range files {
		b, _ := os.ReadFile(p)
		w, _ := zw.Create(filepath.Base(p))
		_, _ = w.Write(b)
	}
	_ = zw.Close()
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSink{}
	if _, err := ParseOSVZip(zr, "osv", map[string]bool{"ubuntu:24.04": true, "rocky:9": true, "alpine:3.19": true, "almalinux:8": true}, sink); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range sink.aff {
		got = append(got, a.Ecosystem+"|"+a.Package+"|"+a.VulnID+"|"+a.Fixed+"|"+a.Advisory)
	}
	sort.Strings(got)
	want := []string{
		"alpine:3.19|openssl|CVE-2024-5535|3.1.6-r0|ALPINE-CVE-2024-5535",
		"rocky:9|openssh-server|CVE-2024-6387|8.7p1-38.el9_4.1|RLSA-2024:4312",
		"rocky:9|openssh|CVE-2024-6387|8.7p1-38.el9_4.1|RLSA-2024:4312",
		"ubuntu:24.04|openssh|CVE-2024-6387|1:9.6p1-3ubuntu13.3|UBUNTU-CVE-2024-6387",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if i := sink.info["CVE-2024-6387"]; i.CVSSScore != 8.1 || i.Severity != "high" {
		t.Fatalf("info %+v", i)
	}
}

func TestKEVEPSSNVDGolden(t *testing.T) {
	f, _ := os.Open(fixtures + "kev.json")
	defer f.Close()
	kev, err := ParseKEV(f)
	if err != nil || len(kev) != 2 || kev[0].CVE != "CVE-2024-6387" || kev[1].Ransomware != "Known" {
		t.Fatalf("%+v %v", kev, err)
	}
	raw, _ := os.ReadFile(fixtures + "epss.csv")
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	var rows []EPSSEntry
	n, err := ParseEPSS(&gz, func(e EPSSEntry) error { rows = append(rows, e); return nil })
	if err != nil || n != 3 || rows[0].Percentile != 0.9941 {
		t.Fatalf("%v %v", rows, err)
	}
	nf, _ := os.Open(fixtures + "nvd-CVE-2024-5535.json")
	defer nf.Close()
	info, err := ParseNVDCVE(nf)
	if err != nil || info.CVSSScore != 9.1 || info.Severity != "critical" || !strings.HasPrefix(info.Summary, "Issue summary") || strings.Contains(info.Summary, "More text") {
		t.Fatalf("%+v %v", info, err)
	}
}

func TestNormalizeOSVEcosystem(t *testing.T) {
	for in, want := range map[string]string{"Debian:12": "debian:12", "Ubuntu:22.04:LTS": "ubuntu:22.04", "Alpine:v3.20": "alpine:3.20", "Rocky Linux:8": "rocky:8", "AlmaLinux:9": "almalinux:9", "Ubuntu:Pro:18.04:LTS": "", "PyPI": ""} {
		got, _ := NormalizeOSVEcosystem(in)
		if got != want {
			t.Errorf("%s → %q", in, got)
		}
	}
}

func TestRHELCrossSink(t *testing.T) {
	m := &memSink{}
	s := RHELCrossSink{Inner: m, AlmaWanted: map[string]bool{}, RockyMajor: map[string]bool{"9": true}}
	_ = s.Affected(Affected{Ecosystem: "almalinux:9", Package: "java-1.8.0-openjdk", VulnID: "CVE-1", Fixed: "1:1.8.0.482.b08-1.el9.alma.1"})
	_ = s.Affected(Affected{Ecosystem: "almalinux:8", Package: "x", VulnID: "CVE-2", Fixed: "1"})
	if len(m.aff) != 1 || m.aff[0].Ecosystem != "rocky:9" || m.aff[0].Fixed != "1:1.8.0.482.b08-1.el9" {
		t.Fatalf("%+v", m.aff)
	}
}
