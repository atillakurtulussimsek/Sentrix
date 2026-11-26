// Package collect contains the agent's metric and state collectors. All readers take a
// procRoot so they can be tested against fixture /proc trees.
package collect

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

// Collector produces metric samples. Implementations may keep state between calls
// to compute rates; the first call of a rate collector may return no samples.
type Collector interface {
	Name() string
	Collect(now time.Time) ([]protocol.Sample, error)
}

// Labels encodes label pairs as a stable "k=v,k=v" string.
func Labels(kv ...string) string {
	if len(kv) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		v := strings.NewReplacer(",", "_", "=", "_").Replace(kv[i+1])
		pairs = append(pairs, kv[i]+"="+v)
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ",")
}

func sample(now time.Time, name, labels string, v float64) protocol.Sample {
	return protocol.Sample{TS: now.Unix(), Name: name, Labels: labels, Value: v}
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out, sc.Err()
}

func parseU(s string) uint64 {
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}

func round2(f float64) float64 {
	return float64(int64(f*100+0.5)) / 100
}

// rateOf computes a per-second rate from two counters, handling wrap/reset.
func rateOf(prev, cur uint64, dt float64) float64 {
	if dt <= 0 || cur < prev {
		return 0
	}
	return float64(cur-prev) / dt
}

func procPath(root string, parts ...string) string {
	return filepath.Join(append([]string{root}, parts...)...)
}
