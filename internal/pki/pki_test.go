package pki

import (
	"crypto/tls"
	"testing"
	"time"
)

func TestCAIssueAndVerify(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := LoadOrCreateCA(dir)
	if err != nil || ca2.Fingerprint() != ca.Fingerprint() {
		t.Fatalf("reload changed CA: %v", err)
	}
	keyPEM, csrPEM, err := NewKeyAndCSR("host")
	if err != nil {
		t.Fatal(err)
	}
	cert, certPEM, err := ca.SignAgentCSR(csrPEM, "agent-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "agent-1" {
		t.Fatalf("cn = %s", cert.Subject.CommonName)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	// An agent certificate must not pass as a server certificate.
	verify := VerifyServerChain(ca.Pool())
	if err := verify([][]byte{cert.Raw}, nil); err == nil {
		t.Fatal("agent cert accepted as server cert")
	}
	srv, err := ca.ServerCertificate([]string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(srv.Certificate, nil); err != nil {
		t.Fatalf("server cert rejected: %v", err)
	}
	// Certificate from another CA must fail.
	other, _ := LoadOrCreateCA(t.TempDir())
	osrv, _ := other.ServerCertificate([]string{"localhost"})
	if err := verify(osrv.Certificate, nil); err == nil {
		t.Fatal("foreign server cert accepted")
	}
}

func TestBadCSR(t *testing.T) {
	ca, _ := LoadOrCreateCA(t.TempDir())
	if _, _, err := ca.SignAgentCSR([]byte("garbage"), "a", time.Hour); err == nil {
		t.Fatal("expected error")
	}
}
