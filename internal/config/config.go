// Package config loads server and agent configuration from YAML files with
// SENTRIX_* environment variable overrides.
package config

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Server is the sentrix-server configuration.
type Server struct {
	DataDir string `yaml:"data_dir" env:"SENTRIX_DATA_DIR"`
	// HTTP listener for the web UI and REST API (put a TLS reverse proxy in front, or set tls_cert/tls_key).
	Listen  string `yaml:"listen" env:"SENTRIX_LISTEN"`
	TLSCert string `yaml:"tls_cert" env:"SENTRIX_TLS_CERT"`
	TLSKey  string `yaml:"tls_key" env:"SENTRIX_TLS_KEY"`
	// Public base URL of the UI (used in notifications and for secure cookies).
	BaseURL string `yaml:"base_url" env:"SENTRIX_BASE_URL"`
	// Agent gateway (mTLS) listener and the names/IPs agents use to reach it.
	GatewayListen string   `yaml:"gateway_listen" env:"SENTRIX_GATEWAY_LISTEN"`
	GatewayHosts  []string `yaml:"gateway_hosts" env:"SENTRIX_GATEWAY_HOSTS"`
	// Public gateway URL shown in the agent install command.
	GatewayURL string `yaml:"gateway_url" env:"SENTRIX_GATEWAY_URL"`

	OfflineAfter      time.Duration `yaml:"offline_after" env:"SENTRIX_OFFLINE_AFTER"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval" env:"SENTRIX_HEARTBEAT_INTERVAL"`
	AgentCertValidity time.Duration `yaml:"agent_cert_validity" env:"SENTRIX_AGENT_CERT_VALIDITY"`

	Retention Retention `yaml:"retention"`
	Feeds     Feeds     `yaml:"feeds"`
	LogLevel  string    `yaml:"log_level" env:"SENTRIX_LOG_LEVEL"`
	// Directory with agent binaries (sentrix-agent-linux-amd64, -arm64) served at
	// /download/ for the install.sh one-liner. Empty disables downloads.
	AgentDir string `yaml:"agent_dir" env:"SENTRIX_AGENT_DIR"`
	// Default UI/notification/CLI language: "tr" (default) or "en". Users can override it per account.
	Language string `yaml:"language" env:"SENTRIX_LANGUAGE"`
	// Insecure cookies for plain-HTTP local development only.
	DevInsecureCookies bool `yaml:"dev_insecure_cookies" env:"SENTRIX_DEV_INSECURE_COOKIES"`
}

// Retention configures metric rollups.
type Retention struct {
	Raw    time.Duration `yaml:"raw" env:"SENTRIX_RETENTION_RAW"`
	Minute time.Duration `yaml:"minute" env:"SENTRIX_RETENTION_MINUTE"`
	Hour   time.Duration `yaml:"hour" env:"SENTRIX_RETENTION_HOUR"`
}

// Feeds configures vulnerability feed synchronisation.
type Feeds struct {
	Enabled      bool          `yaml:"enabled" env:"SENTRIX_FEEDS_ENABLED"`
	Interval     time.Duration `yaml:"interval" env:"SENTRIX_FEEDS_INTERVAL"`
	NVDAPIKey    string        `yaml:"nvd_api_key" env:"SENTRIX_NVD_API_KEY"`
	OSVBaseURL   string        `yaml:"osv_base_url" env:"SENTRIX_OSV_BASE_URL"`
	DebianURL    string        `yaml:"debian_url" env:"SENTRIX_DEBIAN_URL"`
	KEVURL       string        `yaml:"kev_url" env:"SENTRIX_KEV_URL"`
	EPSSURL      string        `yaml:"epss_url" env:"SENTRIX_EPSS_URL"`
	NVDURL       string        `yaml:"nvd_url" env:"SENTRIX_NVD_URL"`
	Ecosystems   []string      `yaml:"ecosystems" env:"SENTRIX_FEEDS_ECOSYSTEMS"`
	OfflineAfter time.Duration `yaml:"stale_after" env:"SENTRIX_FEEDS_STALE_AFTER"`
}

// DefaultServer returns defaults.
func DefaultServer() Server {
	return Server{
		DataDir:           "./data",
		Listen:            ":8080",
		BaseURL:           "http://localhost:8080",
		GatewayListen:     ":8443",
		GatewayHosts:      []string{"localhost", "127.0.0.1"},
		GatewayURL:        "https://localhost:8443",
		OfflineAfter:      60 * time.Second,
		HeartbeatInterval: 15 * time.Second,
		AgentCertValidity: 365 * 24 * time.Hour,
		Retention:         Retention{Raw: 24 * time.Hour, Minute: 7 * 24 * time.Hour, Hour: 90 * 24 * time.Hour},
		Feeds: Feeds{
			Enabled:      true,
			Interval:     6 * time.Hour,
			OSVBaseURL:   "https://osv-vulnerabilities.storage.googleapis.com",
			DebianURL:    "https://security-tracker.debian.org/tracker/data/json",
			KEVURL:       "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
			EPSSURL:      "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
			NVDURL:       "https://services.nvd.nist.gov/rest/json/cves/2.0",
			OfflineAfter: 72 * time.Hour,
		},
		LogLevel: "info",
		Language: "tr",
	}
}

// Agent is the sentrix-agent configuration.
type Agent struct {
	ServerURL      string        `yaml:"server_url" env:"SENTRIX_SERVER_URL"`
	Hostname       string        `yaml:"hostname" env:"SENTRIX_HOSTNAME"`
	StateDir       string        `yaml:"state_dir" env:"SENTRIX_STATE_DIR"`
	Interval       time.Duration `yaml:"interval" env:"SENTRIX_INTERVAL"`
	SendInterval   time.Duration `yaml:"send_interval" env:"SENTRIX_SEND_INTERVAL"`
	BufferMaxMB    int           `yaml:"buffer_max_mb" env:"SENTRIX_BUFFER_MAX_MB"`
	WatchServices  []string      `yaml:"watch_services" env:"SENTRIX_WATCH_SERVICES"`
	TLSEndpoints   []string      `yaml:"tls_endpoints" env:"SENTRIX_TLS_ENDPOINTS"`
	ProcRoot       string        `yaml:"proc_root" env:"SENTRIX_PROC_ROOT"`
	DockerSocket   string        `yaml:"docker_socket" env:"SENTRIX_DOCKER_SOCKET"`
	InventoryEvery time.Duration `yaml:"inventory_interval" env:"SENTRIX_INVENTORY_INTERVAL"`
	// AllowPatching must be true for the agent to execute patch/reboot/restart actions.
	AllowPatching bool   `yaml:"allow_patching" env:"SENTRIX_ALLOW_PATCHING"`
	LogLevel      string `yaml:"log_level" env:"SENTRIX_LOG_LEVEL"`
}

// DefaultAgent returns agent defaults.
func DefaultAgent() Agent {
	return Agent{
		StateDir:       "/var/lib/sentrix-agent",
		Interval:       10 * time.Second,
		SendInterval:   30 * time.Second,
		BufferMaxMB:    50,
		ProcRoot:       "/proc",
		DockerSocket:   "/var/run/docker.sock",
		InventoryEvery: 6 * time.Hour,
		AllowPatching:  true,
		LogLevel:       "info",
	}
}

// Load reads YAML from path (optional when empty) into dst, then applies env overrides.
func Load(path string, dst any) error {
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(b, dst); err != nil {
			return fmt.Errorf("parse config %s: %w", path, err)
		}
	}
	return applyEnv(reflect.ValueOf(dst).Elem())
}

func applyEnv(v reflect.Value) error {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f, fv := t.Field(i), v.Field(i)
		if f.Type.Kind() == reflect.Struct && f.Type != reflect.TypeFor[time.Duration]() {
			if err := applyEnv(fv); err != nil {
				return err
			}
			continue
		}
		name := f.Tag.Get("env")
		raw, ok := os.LookupEnv(name)
		if name == "" || !ok {
			continue
		}
		switch {
		case f.Type == reflect.TypeFor[time.Duration]():
			d, err := time.ParseDuration(raw)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			fv.SetInt(int64(d))
		case f.Type.Kind() == reflect.String:
			fv.SetString(raw)
		case f.Type.Kind() == reflect.Bool:
			b, err := strconv.ParseBool(raw)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			fv.SetBool(b)
		case f.Type.Kind() == reflect.Int:
			n, err := strconv.Atoi(raw)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			fv.SetInt(int64(n))
		case f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.String:
			var parts []string
			for _, p := range strings.Split(raw, ",") {
				if p = strings.TrimSpace(p); p != "" {
					parts = append(parts, p)
				}
			}
			fv.Set(reflect.ValueOf(parts))
		}
	}
	return nil
}
