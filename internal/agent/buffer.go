package agent

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

// Buffer is a bounded on-disk FIFO of metric batches. Every collected batch is written
// here first and removed only after the server acknowledged it, so data survives
// network outages and agent restarts. When the size cap is exceeded the oldest
// batches are dropped.
type Buffer struct {
	dir      string
	maxBytes int64
	mu       sync.Mutex
	seq      int
}

// NewBuffer opens (creating) a buffer directory.
func NewBuffer(dir string, maxBytes int64) (*Buffer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Buffer{dir: dir, maxBytes: maxBytes}, nil
}

// Put appends a batch.
func (b *Buffer) Put(batch protocol.MetricsBatch) error {
	if len(batch.Samples) == 0 {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seq++
	name := fmt.Sprintf("%020d-%06d.json.gz", time.Now().UnixNano(), b.seq%1000000)
	tmp := filepath.Join(b.dir, "."+name)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(f)
	if err := json.NewEncoder(zw).Encode(batch); err != nil {
		_ = f.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(b.dir, name)); err != nil {
		return err
	}
	return b.enforceCap()
}

func (b *Buffer) files() ([]string, int64) {
	ents, _ := os.ReadDir(b.dir)
	var names []string
	var total int64
	for _, e := range ents {
		if e.IsDir() || e.Name()[0] == '.' {
			continue
		}
		if info, err := e.Info(); err == nil {
			total += info.Size()
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, total
}

func (b *Buffer) enforceCap() error {
	names, total := b.files()
	for len(names) > 0 && total > b.maxBytes {
		p := filepath.Join(b.dir, names[0])
		if info, err := os.Stat(p); err == nil {
			total -= info.Size()
		}
		if err := os.Remove(p); err != nil {
			return err
		}
		names = names[1:]
	}
	return nil
}

// Len returns the number of buffered batches.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, _ := b.files()
	return len(n)
}

// Drain calls send for each batch oldest-first and deletes it on success. It stops at the
// first error. Corrupt files are discarded.
func (b *Buffer) Drain(send func(protocol.MetricsBatch) error) (int, error) {
	b.mu.Lock()
	names, _ := b.files()
	b.mu.Unlock()
	sent := 0
	for _, n := range names {
		p := filepath.Join(b.dir, n)
		batch, err := readBatch(p)
		if err != nil {
			_ = os.Remove(p)
			continue
		}
		if err := send(batch); err != nil {
			return sent, err
		}
		_ = os.Remove(p)
		sent++
	}
	return sent, nil
}

func readBatch(p string) (protocol.MetricsBatch, error) {
	var batch protocol.MetricsBatch
	f, err := os.Open(p)
	if err != nil {
		return batch, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return batch, err
	}
	defer zr.Close()
	return batch, json.NewDecoder(zr).Decode(&batch)
}
