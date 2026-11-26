package agent

import (
	"errors"
	"testing"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

func batchOf(n int) protocol.MetricsBatch {
	var b protocol.MetricsBatch
	for i := 0; i < n; i++ {
		b.Samples = append(b.Samples, protocol.Sample{TS: int64(i), Name: "cpu.usage", Value: float64(i)})
	}
	return b
}

func TestBufferDrainOrderAndRetry(t *testing.T) {
	b, err := NewBuffer(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if err := b.Put(batchOf(i)); err != nil {
			t.Fatal(err)
		}
	}
	fail := errors.New("offline")
	var got []int
	n, err := b.Drain(func(m protocol.MetricsBatch) error {
		if len(m.Samples) == 2 {
			return fail
		}
		got = append(got, len(m.Samples))
		return nil
	})
	if !errors.Is(err, fail) || n != 1 || b.Len() != 2 {
		t.Fatalf("n=%d err=%v len=%d", n, err, b.Len())
	}
	n, err = b.Drain(func(m protocol.MetricsBatch) error { got = append(got, len(m.Samples)); return nil })
	if err != nil || n != 2 || b.Len() != 0 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Fatalf("n=%d got=%v", n, got)
	}
}

func TestBufferCap(t *testing.T) {
	b, _ := NewBuffer(t.TempDir(), 3000)
	for i := 0; i < 50; i++ {
		_ = b.Put(batchOf(200))
	}
	_, total := b.files()
	if total > 3000 || b.Len() == 0 {
		t.Fatalf("total=%d len=%d", total, b.Len())
	}
}
