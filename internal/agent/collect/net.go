package collect

import (
	"strings"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

type netCounters struct{ rxB, rxP, rxE, rxD, txB, txP, txE, txD uint64 }

// Network reports per-interface throughput and error rates from /proc/net/dev.
type Network struct {
	ProcRoot string
	prev     map[string]netCounters
	prevAt   time.Time
}

// Name implements Collector.
func (n *Network) Name() string { return "network" }

func skipIface(name string) bool {
	if name == "lo" {
		return true
	}
	for _, p := range []string{"veth", "docker", "br-", "virbr", "cali", "flannel", "cni", "vxlan", "tap", "fwbr", "fwpr", "fwln"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Collect implements Collector.
func (n *Network) Collect(now time.Time) ([]protocol.Sample, error) {
	lines, err := readLines(procPath(n.ProcRoot, "net", "dev"))
	if err != nil {
		return nil, err
	}
	cur := map[string]netCounters{}
	for _, l := range lines {
		name, rest, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		f := strings.Fields(rest)
		if len(f) < 16 || skipIface(name) {
			continue
		}
		cur[name] = netCounters{parseU(f[0]), parseU(f[1]), parseU(f[2]), parseU(f[3]), parseU(f[8]), parseU(f[9]), parseU(f[10]), parseU(f[11])}
	}
	var out []protocol.Sample
	if n.prev != nil {
		dt := now.Sub(n.prevAt).Seconds()
		for name, c := range cur {
			p, ok := n.prev[name]
			if !ok {
				continue
			}
			lb := Labels("iface", name)
			out = append(out,
				sample(now, "net.rx_bps", lb, round2(rateOf(p.rxB, c.rxB, dt))),
				sample(now, "net.tx_bps", lb, round2(rateOf(p.txB, c.txB, dt))),
				sample(now, "net.rx_pps", lb, round2(rateOf(p.rxP, c.rxP, dt))),
				sample(now, "net.tx_pps", lb, round2(rateOf(p.txP, c.txP, dt))),
				sample(now, "net.errors", lb, round2(rateOf(p.rxE+p.txE, c.rxE+c.txE, dt))),
				sample(now, "net.drops", lb, round2(rateOf(p.rxD+p.txD, c.rxD+c.txD, dt))),
			)
		}
	}
	n.prev, n.prevAt = cur, now
	return out, nil
}
