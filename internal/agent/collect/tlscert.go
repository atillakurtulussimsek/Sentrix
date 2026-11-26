package collect

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

// CheckCerts dials each host:port endpoint and records the leaf certificate expiry.
func CheckCerts(ctx context.Context, endpoints []string) []protocol.CertStatus {
	var out []protocol.CertStatus
	for _, ep := range endpoints {
		addr := ep
		if !strings.Contains(addr, ":") {
			addr += ":443"
		}
		host, _, _ := net.SplitHostPort(addr)
		st := protocol.CertStatus{Endpoint: ep}
		d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: &tls.Config{
			ServerName: host, MinVersion: tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // we only read expiry, never send data
		}}
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		conn, err := d.DialContext(cctx, "tcp", addr)
		cancel()
		if err != nil {
			st.Error = err.Error()
			out = append(out, st)
			continue
		}
		if tc, ok := conn.(*tls.Conn); ok {
			if certs := tc.ConnectionState().PeerCertificates; len(certs) > 0 {
				st.Subject, st.NotAfter = certs[0].Subject.CommonName, certs[0].NotAfter
			}
		}
		_ = conn.Close()
		out = append(out, st)
	}
	return out
}
