package patch

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// HookTarget identifies the host a pre-patch hook acts on.
type HookTarget struct {
	PlanID   string `json:"plan_id"`
	PlanName string `json:"plan_name"`
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	// Proxmox mapping from host settings: node name and VM ID ("105" for QEMU,
	// "lxc/105" for a container).
	ProxmoxNode string `json:"-"`
	ProxmoxVMID string `json:"-"`
}

// ProxmoxConfig configures the Proxmox VE snapshot hook (API token auth).
type ProxmoxConfig struct {
	URL         string `json:"url"`          // https://pve.example.com:8006
	TokenID     string `json:"token_id"`     // user@realm!tokenname
	TokenSecret string `json:"token_secret"` // UUID (sealed at rest)
	// DefaultNode is used when the host has no node mapping.
	DefaultNode string `json:"default_node,omitempty"`
	// Insecure skips TLS verification (self-signed PVE certificates). Prefer CAFingerprint.
	Insecure bool `json:"insecure,omitempty"`
	// CAFingerprint pins the PVE certificate (hex SHA-256 of the leaf, colons allowed).
	CAFingerprint string `json:"ca_fingerprint,omitempty"`
	// VMState includes RAM in QEMU snapshots.
	VMState bool `json:"vmstate,omitempty"`
}

// WebhookConfig configures the generic pre-patch webhook hook.
type WebhookConfig struct {
	URL    string `json:"url"`
	Secret string `json:"secret,omitempty"` // HMAC-SHA256 signing secret (sealed at rest)
}

var snapNameRe = regexp.MustCompile(`[^A-Za-z0-9_-]`)

// SnapshotName builds a Proxmox-compatible snapshot name (letter first, ≤40 chars).
func SnapshotName(planID string, t time.Time) string {
	id := snapNameRe.ReplaceAllString(planID, "")
	if len(id) > 8 {
		id = id[:8]
	}
	return "sentrix-" + id + "-" + t.UTC().Format("20060102T1504")
}

func (c ProxmoxConfig) client() *http.Client {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFingerprint != "" {
		want := strings.ToLower(strings.ReplaceAll(c.CAFingerprint, ":", ""))
		tc.InsecureSkipVerify = true //nolint:gosec // replaced by fingerprint pinning below
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if hex.EncodeToString(sum[:]) != want {
				return errors.New("proxmox certificate fingerprint mismatch")
			}
			return nil
		}
	} else if c.Insecure {
		tc.InsecureSkipVerify = true //nolint:gosec // explicit opt-in for self-signed PVE
	}
	return &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}
}

type pveResp struct {
	Data   json.RawMessage `json:"data"`
	Errors map[string]any  `json:"errors"`
}

func (c ProxmoxConfig) call(ctx context.Context, hc *http.Client, method, path string, form url.Values) (json.RawMessage, error) {
	u := strings.TrimRight(c.URL, "/") + "/api2/json" + path
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "PVEAPIToken="+c.TokenID+"="+c.TokenSecret)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("proxmox %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("proxmox %s %s: HTTP %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var r pveResp
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("proxmox: invalid response: %w", err)
	}
	return r.Data, nil
}

// Validate checks the configuration.
func (c ProxmoxConfig) Validate() error {
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("proxmox URL must be https://host:8006")
	}
	if !strings.Contains(c.TokenID, "!") || c.TokenSecret == "" {
		return errors.New("proxmox API token id (user@realm!name) and secret are required")
	}
	return nil
}

// Ping checks connectivity and credentials (GET /version).
func (c ProxmoxConfig) Ping(ctx context.Context) (string, error) {
	data, err := c.call(ctx, c.client(), http.MethodGet, "/version", nil)
	if err != nil {
		return "", err
	}
	var v struct {
		Version string `json:"version"`
	}
	_ = json.Unmarshal(data, &v)
	return v.Version, nil
}

var vmidRe = regexp.MustCompile(`^(?:(qemu|lxc)/)?(\d{2,9})$`)

// Snapshot creates a snapshot of the host's VM/container and waits for the task to finish.
func (c ProxmoxConfig) Snapshot(ctx context.Context, t HookTarget, now time.Time) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	node := t.ProxmoxNode
	if node == "" {
		node = c.DefaultNode
	}
	m := vmidRe.FindStringSubmatch(strings.TrimSpace(t.ProxmoxVMID))
	if node == "" || m == nil {
		return "", fmt.Errorf("host %s has no Proxmox node/VM ID mapping (host settings)", t.Hostname)
	}
	kind := m[1]
	if kind == "" {
		kind = "qemu"
	}
	name := SnapshotName(t.PlanID, now)
	form := url.Values{"snapname": {name}, "description": {"Sentrix pre-patch snapshot · plan " + t.PlanName}}
	if kind == "qemu" && c.VMState {
		form.Set("vmstate", "1")
	}
	hc := c.client()
	data, err := c.call(ctx, hc, http.MethodPost, "/nodes/"+url.PathEscape(node)+"/"+kind+"/"+m[2]+"/snapshot", form)
	if err != nil {
		return "", err
	}
	var upid string
	if err := json.Unmarshal(data, &upid); err != nil || upid == "" {
		return "", errors.New("proxmox: no task id returned")
	}
	for {
		sd, err := c.call(ctx, hc, http.MethodGet, "/nodes/"+url.PathEscape(node)+"/tasks/"+url.PathEscape(upid)+"/status", nil)
		if err != nil {
			return "", err
		}
		var st struct {
			Status     string `json:"status"`
			ExitStatus string `json:"exitstatus"`
		}
		_ = json.Unmarshal(sd, &st)
		if st.Status == "stopped" {
			if st.ExitStatus != "OK" {
				return "", fmt.Errorf("proxmox snapshot task failed: %s", st.ExitStatus)
			}
			return name, nil
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("proxmox snapshot: %w", ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
}

// CallWebhook posts the pre-patch event; any 2xx response means success. The response
// may contain {"snapshot": "<name>"} to record what was created.
func (c WebhookConfig) CallWebhook(ctx context.Context, t HookTarget) (string, error) {
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", errors.New("invalid webhook URL")
	}
	body, _ := json.Marshal(map[string]any{"event": "pre_patch", "target": t, "time": time.Now().UTC()})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Secret != "" {
		mac := hmac.New(sha256.New, []byte(c.Secret))
		mac.Write(body)
		req.Header.Set("X-Sentrix-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		return "", fmt.Errorf("webhook: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("webhook returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var r struct {
		Snapshot string `json:"snapshot"`
	}
	_ = json.Unmarshal(b, &r)
	if r.Snapshot == "" {
		r.Snapshot = "webhook ok"
	}
	return r.Snapshot, nil
}
