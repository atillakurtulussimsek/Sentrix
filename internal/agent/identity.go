// Package agent implements sentrix-agent: enrolment, collectors, buffering,
// server communication and the typed action executor.
package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/pki"
	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

// Identity is the agent's persisted enrolment state.
type Identity struct {
	AgentID   string `json:"agent_id"`
	ServerURL string `json:"server_url"`
	// Hostname overrides os.Hostname() when set at enrolment (--hostname).
	Hostname string `json:"hostname,omitempty"`
}

const (
	fileIdentity = "identity.json"
	fileKey      = "agent.key"
	fileCert     = "agent.crt"
	fileCA       = "ca.crt"
)

// LoadIdentity reads the identity from stateDir.
func LoadIdentity(stateDir string) (Identity, error) {
	var id Identity
	b, err := os.ReadFile(filepath.Join(stateDir, fileIdentity))
	if err != nil {
		return id, err
	}
	return id, json.Unmarshal(b, &id)
}

// Enrolled reports whether stateDir contains a usable identity.
func Enrolled(stateDir string) bool {
	_, err := LoadIdentity(stateDir)
	return err == nil
}

func pinnedTLS(caPEM []byte) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid CA PEM")
	}
	// Standard verification is replaced (not skipped): VerifyServerChain checks the chain
	// against the pinned private CA and requires ServerAuth key usage. Hostnames are not
	// checked because agents may reach the gateway via NAT/IP addresses.
	verify := pki.VerifyServerChain(pool)
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // replaced by VerifyConnection below
		VerifyConnection: func(cs tls.ConnectionState) error {
			raw := make([][]byte, len(cs.PeerCertificates))
			for i, c := range cs.PeerCertificates {
				raw[i] = c.Raw
			}
			return verify(raw, nil)
		},
	}, nil
}

// Enroll performs first-time enrolment with a one-time token. caFingerprint (hex SHA-256
// of the server CA, shown in the UI) is required to bootstrap trust. A non-empty
// fixedHostname is persisted and reported instead of the OS hostname.
func Enroll(ctx context.Context, stateDir, serverURL, token, caFingerprint, hostname, machineID string, fixedHostname ...string) (Identity, error) {
	serverURL = strings.TrimRight(serverURL, "/")
	caFingerprint = strings.ToLower(strings.ReplaceAll(caFingerprint, ":", ""))
	if caFingerprint == "" {
		return Identity{}, errors.New("--ca-fingerprint is required for enrolment")
	}
	// 1. Fetch CA without verification and check it against the out-of-band fingerprint.
	bootstrap := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // CA verified by fingerprint below
	}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+protocol.PathCA, nil)
	resp, err := bootstrap.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("fetch CA: %w", err)
	}
	caPEM, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if err != nil {
		return Identity{}, err
	}
	caCert, err := pki.ParseCertPEM(caPEM)
	if err != nil {
		return Identity{}, fmt.Errorf("parse CA: %w", err)
	}
	if got := pki.Fingerprint(caCert); got != caFingerprint {
		return Identity{}, fmt.Errorf("CA fingerprint mismatch: server presented %s", got)
	}
	// 2. Enrol over a connection pinned to that CA.
	tlsCfg, err := pinnedTLS(caPEM)
	if err != nil {
		return Identity{}, err
	}
	keyPEM, csrPEM, err := pki.NewKeyAndCSR(hostname)
	if err != nil {
		return Identity{}, err
	}
	body, _ := json.Marshal(protocol.EnrollRequest{Token: token, Hostname: hostname, MachineID: machineID, CSRPEM: string(csrPEM)})
	c := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, serverURL+protocol.PathEnroll, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err = c.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("enrol: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return Identity{}, fmt.Errorf("enrol rejected (%d): %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var er protocol.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return Identity{}, err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return Identity{}, err
	}
	id := Identity{AgentID: er.AgentID, ServerURL: serverURL}
	if len(fixedHostname) > 0 {
		id.Hostname = fixedHostname[0]
	}
	idb, _ := json.MarshalIndent(id, "", "  ")
	for name, data := range map[string][]byte{fileKey: keyPEM, fileCert: []byte(er.CertPEM), fileCA: caPEM, fileIdentity: idb} {
		if err := os.WriteFile(filepath.Join(stateDir, name), data, 0o600); err != nil {
			return Identity{}, fmt.Errorf("write %s: %w", name, err)
		}
	}
	return id, nil
}

// mtlsClient builds an HTTP client presenting the agent certificate.
func mtlsClient(stateDir string, timeout time.Duration) (*http.Client, *x509.Certificate, error) {
	caPEM, err := os.ReadFile(filepath.Join(stateDir, fileCA))
	if err != nil {
		return nil, nil, err
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(stateDir, fileCert), filepath.Join(stateDir, fileKey))
	if err != nil {
		return nil, nil, fmt.Errorf("load agent certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	tlsCfg, err := pinnedTLS(caPEM)
	if err != nil {
		return nil, nil, err
	}
	tlsCfg.Certificates = []tls.Certificate{cert}
	tr := &http.Transport{TLSClientConfig: tlsCfg, ForceAttemptHTTP2: true, MaxIdleConns: 2, IdleConnTimeout: 90 * time.Second}
	return &http.Client{Timeout: timeout, Transport: tr}, leaf, nil
}
