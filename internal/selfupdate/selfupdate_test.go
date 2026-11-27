package selfupdate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bin := []byte("\x7fELF fake agent")
	m := Sign(priv, "0.2.0", "amd64", bin)
	if m.Version != "v0.2.0" {
		t.Fatalf("version not normalized: %q", m.Version)
	}
	if err := VerifyManifest(m, pub); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBinary(m, bytes.NewReader(bin)); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBinary(m, bytes.NewReader([]byte("\x7fELF evil  agent"))); err == nil {
		t.Fatal("tampered binary accepted")
	}
	// Signature must not be replayable for another version or architecture.
	for _, bad := range []Manifest{
		{Version: "v0.3.0", Arch: m.Arch, SHA256: m.SHA256, Size: m.Size, Signature: m.Signature},
		{Version: m.Version, Arch: "arm64", SHA256: m.SHA256, Size: m.Size, Signature: m.Signature},
	} {
		if err := VerifyManifest(bad, pub); err == nil {
			t.Fatalf("replayed signature accepted: %+v", bad)
		}
	}
	// A key other than the release key must be rejected by default.
	if err := VerifyManifest(m, nil); err == nil {
		t.Fatal("manifest signed with a foreign key accepted by the release key")
	}
}

func TestMalformedManifestRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := Sign(priv, "v0.2.0", "amd64", []byte("x"))
	m.Version = "v0.2.0-rc1"
	if err := VerifyManifest(m, pub); err == nil {
		t.Fatal("non-release version accepted")
	}
	if _, err := ParseManifest([]byte(`{"version":"v1.0.0","extra":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v0.1.0", "v0.2.0", -1},
		{"0.2.0", "v0.2.0", 0},
		{"v0.1.0-12-gffb2407", "v0.1.0", 1},
		{"v0.1.0-12-gffb2407-dirty", "v0.1.1", -1},
		{"dev", "v0.0.1", -1},
		{"v1.10.0", "v1.9.9", 1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
	if GoArch("x86_64") != "amd64" || GoArch("aarch64") != "arm64" || GoArch("riscv64") != "" {
		t.Fatal("GoArch mapping")
	}
}
