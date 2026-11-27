// Package selfupdate verifies signed sentrix-agent releases.
//
// Release binaries are signed in CI with the Varkhe Digital release key (Ed25519). The
// public key is compiled into every agent, so an agent only installs binaries produced
// by the official release pipeline: a compromised Sentrix server can offer an update
// but cannot forge one, which preserves the "no arbitrary code from the server" model.
package selfupdate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// ReleasePublicKey is the Varkhe Digital agent release signing key (Ed25519, base64).
const ReleasePublicKey = "JSsZCRruq/IS57EFNHM+2bOaBS0pXD1iBaDzYljr+Rk="

// Arches are the agent architectures that are built and signed.
var Arches = []string{"amd64", "arm64"}

// Manifest describes one signed agent binary; it is published next to the binary
// as "<binary>.sig.json".
type Manifest struct {
	Version   string `json:"version"`   // release version, e.g. v0.2.0
	Arch      string `json:"arch"`      // amd64 | arm64
	SHA256    string `json:"sha256"`    // hex digest of the binary
	Size      int64  `json:"size"`      // binary size in bytes
	Signature string `json:"signature"` // base64 Ed25519 signature over Message()
}

// BinaryName returns the published file name of the agent binary for arch.
func BinaryName(arch string) string { return "sentrix-agent-linux-" + arch }

// ManifestName returns the published file name of the manifest for arch.
func ManifestName(arch string) string { return BinaryName(arch) + ".sig.json" }

// Message is the exact byte string that is signed: it binds the digest to the
// version and architecture so a signature cannot be replayed for another release.
func Message(version, arch, sha string, size int64) []byte {
	return fmt.Appendf(nil, "sentrix-agent-release/v1\nversion=%s\narch=%s\nsha256=%s\nsize=%d\n", NormalizeVersion(version), arch, strings.ToLower(sha), size)
}

var (
	releaseRe = regexp.MustCompile(`^v\d{1,4}\.\d{1,4}\.\d{1,4}$`)
	shaRe     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidReleaseVersion reports whether v is a plain release version (vX.Y.Z).
func ValidReleaseVersion(v string) bool { return releaseRe.MatchString(NormalizeVersion(v)) }

// ValidArch reports whether arch is a signed agent architecture.
func ValidArch(arch string) bool { return arch == "amd64" || arch == "arm64" }

// ValidSHA256 reports whether s is a lower-case hex SHA-256 digest.
func ValidSHA256(s string) bool { return shaRe.MatchString(s) }

// Sign produces a manifest for a binary (used by the release tooling and tests).
func Sign(priv ed25519.PrivateKey, version, arch string, bin []byte) Manifest {
	sum := sha256.Sum256(bin)
	sha := hex.EncodeToString(sum[:])
	v := NormalizeVersion(version)
	sig := ed25519.Sign(priv, Message(v, arch, sha, int64(len(bin))))
	return Manifest{Version: v, Arch: arch, SHA256: sha, Size: int64(len(bin)), Signature: base64.StdEncoding.EncodeToString(sig)}
}

// ErrBadSignature is returned when a manifest is not signed by the release key.
var ErrBadSignature = errors.New("agent release signature is invalid")

// testKey replaces the release key in tests (see UseTestKey).
var testKey ed25519.PublicKey

// UseTestKey makes VerifyManifest(m, nil) trust pub instead of the release key and
// returns a function restoring it. For tests only: it cannot be reached remotely.
func UseTestKey(pub ed25519.PublicKey) (restore func()) {
	prev := testKey
	testKey = pub
	return func() { testKey = prev }
}

// VerifyManifest checks the manifest fields and its signature against pub
// (nil = the compiled-in ReleasePublicKey).
func VerifyManifest(m Manifest, pub ed25519.PublicKey) error {
	if pub == nil && testKey != nil {
		pub = testKey
	}
	if pub == nil {
		k, err := base64.StdEncoding.DecodeString(ReleasePublicKey)
		if err != nil || len(k) != ed25519.PublicKeySize {
			return errors.New("release public key is malformed")
		}
		pub = k
	}
	if !ValidReleaseVersion(m.Version) || !ValidArch(m.Arch) || !ValidSHA256(m.SHA256) || m.Size <= 0 || m.Size > MaxBinarySize {
		return fmt.Errorf("agent release manifest is malformed: %+v", m)
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil || !ed25519.Verify(pub, Message(m.Version, m.Arch, m.SHA256, m.Size), sig) {
		return ErrBadSignature
	}
	return nil
}

// MaxBinarySize bounds downloads of agent binaries.
const MaxBinarySize = 100 << 20

// VerifyBinary reads r (at most MaxBinarySize) and checks it against a verified manifest.
func VerifyBinary(m Manifest, r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxBinarySize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != m.Size {
		return nil, fmt.Errorf("agent binary size %d does not match manifest %d", len(b), m.Size)
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != m.SHA256 {
		return nil, errors.New("agent binary checksum does not match the signed manifest")
	}
	return b, nil
}

// ParseManifest decodes a manifest strictly.
func ParseManifest(b []byte) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, fmt.Errorf("parse agent release manifest: %w", err)
	}
	return m, nil
}

// NormalizeVersion adds the "v" prefix GoReleaser strips ("0.2.0" → "v0.2.0").
func NormalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v != "" && v[0] >= '0' && v[0] <= '9' {
		return "v" + v
	}
	return v
}

type parsedVersion struct {
	nums    [3]int
	commits int  // commits after the tag (git describe "-N-gHASH")
	ok      bool // false for "dev" and other unparseable strings
}

var describeRe = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)(?:-(\d+)-g[0-9a-f]+)?(?:-dirty)?$`)

func parse(v string) parsedVersion {
	m := describeRe.FindStringSubmatch(NormalizeVersion(v))
	if m == nil {
		return parsedVersion{}
	}
	var p parsedVersion
	for i := 0; i < 3; i++ {
		p.nums[i], _ = strconv.Atoi(m[i+1])
	}
	if m[4] != "" {
		p.commits, _ = strconv.Atoi(m[4])
	}
	p.ok = true
	return p
}

// Compare orders agent versions: release tags (v1.2.3), GoReleaser versions without
// "v", and git-describe builds (v1.2.3-4-gabcdef[-dirty], ordered after v1.2.3 and
// before v1.2.4). Unparseable versions such as "dev" sort before everything.
func Compare(a, b string) int {
	pa, pb := parse(a), parse(b)
	switch {
	case !pa.ok && !pb.ok:
		return 0
	case !pa.ok:
		return -1
	case !pb.ok:
		return 1
	}
	for i := 0; i < 3; i++ {
		if pa.nums[i] != pb.nums[i] {
			if pa.nums[i] < pb.nums[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case pa.commits < pb.commits:
		return -1
	case pa.commits > pb.commits:
		return 1
	}
	return 0
}

// GoArch maps an inventory architecture (uname -m style) to a Go/release arch.
func GoArch(arch string) string {
	switch strings.ToLower(arch) {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	}
	return ""
}
