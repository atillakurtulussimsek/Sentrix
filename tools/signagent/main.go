// Command signagent writes the signed release manifest (<binary>.sig.json) for a
// sentrix-agent binary. It is run by GoReleaser in the release workflow; the private
// key (base64 Ed25519 seed) comes from the SENTRIX_RELEASE_SIGNING_KEY secret.
//
//	signagent -version v0.2.0 -name sentrix-agent-linux-amd64 -in dist/…/sentrix-agent -out dist/sentrix-agent-linux-amd64.sig.json
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/atillakurtulussimsek/Sentrix/internal/selfupdate"
)

func main() {
	version := flag.String("version", "", "release version (vX.Y.Z)")
	in := flag.String("in", "", "agent binary")
	out := flag.String("out", "", "manifest output path")
	name := flag.String("name", "", "published binary name (default: base name of -in), e.g. sentrix-agent-linux-amd64")
	flag.Parse()
	if *name == "" {
		*name = filepath.Base(*in)
	}
	if err := run(*version, *name, *in, *out); err != nil {
		fmt.Fprintln(os.Stderr, "signagent:", err)
		os.Exit(1)
	}
}

func run(version, name, in, out string) error {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("SENTRIX_RELEASE_SIGNING_KEY")))
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("SENTRIX_RELEASE_SIGNING_KEY must be a base64 Ed25519 seed")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if !selfupdate.ValidReleaseVersion(version) {
		return fmt.Errorf("version %q is not a release version", version)
	}
	arch := ""
	for _, a := range selfupdate.Arches {
		if name == selfupdate.BinaryName(a) {
			arch = a
		}
	}
	if arch == "" {
		return fmt.Errorf("cannot infer architecture from %q", name)
	}
	bin, err := os.ReadFile(in) //nolint:gosec // path given by the release pipeline
	if err != nil {
		return err
	}
	m := selfupdate.Sign(priv, version, arch, bin)
	if err := selfupdate.VerifyManifest(m, priv.Public().(ed25519.PublicKey)); err != nil {
		return err
	}
	if err := selfupdate.VerifyManifest(m, nil); err != nil {
		return fmt.Errorf("signing key does not match the public key compiled into the agent: %w", err)
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	return os.WriteFile(out, append(b, '\n'), 0o644) //nolint:gosec // public release artifact
}
