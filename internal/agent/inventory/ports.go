package inventory

import (
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

// ListeningPorts parses /proc/net/{tcp,tcp6,udp,udp6} and maps socket inodes to processes.
func ListeningPorts(procRoot string) []protocol.ListeningPort {
	owners := socketOwners(procRoot)
	var out []protocol.ListeningPort
	seen := map[string]bool{}
	for _, f := range []struct{ file, proto, state string }{
		{"tcp", "tcp", "0A"}, {"tcp6", "tcp", "0A"}, {"udp", "udp", "07"}, {"udp6", "udp", "07"},
	} {
		b, err := os.ReadFile(filepath.Join(procRoot, "net", f.file))
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(b), "\n")[1:] {
			fs := strings.Fields(l)
			if len(fs) < 10 || fs[3] != f.state {
				continue
			}
			addr, port, ok := parseHexAddr(fs[1])
			if !ok || (f.proto == "udp" && port == 0) {
				continue
			}
			lp := protocol.ListeningPort{Proto: f.proto, Address: addr, Port: port}
			if o, ok := owners[fs[9]]; ok {
				lp.PID, lp.Process = o.pid, o.name
			}
			key := lp.Proto + lp.Address + strconv.Itoa(lp.Port)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, lp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Proto < out[j].Proto
	})
	return out
}

// parseHexAddr decodes "0100007F:0035" (little-endian per 32-bit word) into IP and port.
func parseHexAddr(s string) (string, int, bool) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return "", 0, false
	}
	raw, err := hex.DecodeString(a)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", 0, false
	}
	ip := make(net.IP, len(raw))
	for w := 0; w < len(raw); w += 4 {
		ip[w], ip[w+1], ip[w+2], ip[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	return ip.String(), int(port), true
}

type owner struct {
	pid  int
	name string
}

func socketOwners(procRoot string) map[string]owner {
	out := map[string]owner{}
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return out
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join(procRoot, e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		var name string
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			if name == "" {
				b, _ := os.ReadFile(filepath.Join(procRoot, e.Name(), "comm"))
				name = strings.TrimSpace(string(b))
			}
			out[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = owner{pid, name}
		}
	}
	return out
}
