package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadFileAndEnv(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	_ = os.WriteFile(p, []byte("listen: \":9000\"\noffline_after: 30s\nretention:\n  raw: 2h\n"), 0o600)
	t.Setenv("SENTRIX_GATEWAY_HOSTS", "a.example, 10.0.0.1")
	t.Setenv("SENTRIX_RETENTION_HOUR", "48h")
	c := DefaultServer()
	if err := Load(p, &c); err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":9000" || c.OfflineAfter != 30*time.Second || c.Retention.Raw != 2*time.Hour || c.Retention.Hour != 48*time.Hour {
		t.Fatalf("%+v", c)
	}
	if len(c.GatewayHosts) != 2 || c.GatewayHosts[1] != "10.0.0.1" {
		t.Fatalf("hosts %v", c.GatewayHosts)
	}
	if c.Retention.Minute != 7*24*time.Hour {
		t.Fatal("default lost")
	}
}
