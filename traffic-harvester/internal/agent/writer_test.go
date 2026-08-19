package agent

import (
	"context"
	"testing"
	"time"

	"github.com/traffic-harvester/traffic-harvester/internal/storage"
)

func TestBufferedWriter_Write(t *testing.T) {
	w := &mockWriter{}
	bw := NewBufferedWriter(BufferedWriterConfig{
		Writer:        w,
		BatchSize:     3,
		FlushInterval: 10 * time.Second,
	})
	defer bw.Close()

	for i := 0; i < 2; i++ {
		err := bw.Write(context.Background(), &storage.CapturedRequest{
			ID: "req", Method: "GET", Path: "/test",
		})
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	// 2 writes, below batch threshold of 3 → no flush yet
	if w.flushed != 0 {
		t.Errorf("flushed = %d, want 0 (below batch size)", w.flushed)
	}

	// Third write triggers flush
	err := bw.Write(context.Background(), &storage.CapturedRequest{
		ID: "req3", Method: "GET", Path: "/test",
	})
	if err != nil {
		t.Fatalf("write 3: %v", err)
	}

	if w.flushed != 1 {
		t.Errorf("flushed = %d, want 1 (batch threshold)", w.flushed)
	}
}

func TestBufferedWriter_Close(t *testing.T) {
	w := &mockWriter{}
	bw := NewBufferedWriter(BufferedWriterConfig{
		Writer:        w,
		BatchSize:     100,
		FlushInterval: 10 * time.Second,
	})

	_ = bw.Write(context.Background(), &storage.CapturedRequest{
		ID: "req", Method: "GET", Path: "/test",
	})

	if err := bw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if !w.closed {
		t.Error("expected underlying writer to be closed")
	}

	// Writing after close should fail
	err := bw.Write(context.Background(), &storage.CapturedRequest{})
	if err != storage.ErrWriterClosed {
		t.Errorf("write after close: got %v, want ErrWriterClosed", err)
	}
}

func TestBufferedWriter_FlushInterval(t *testing.T) {
	w := &mockWriter{}
	bw := NewBufferedWriter(BufferedWriterConfig{
		Writer:        w,
		BatchSize:     1000,
		FlushInterval: 50 * time.Millisecond,
	})
	defer bw.Close()

	_ = bw.Write(context.Background(), &storage.CapturedRequest{
		ID: "req", Method: "GET", Path: "/test",
	})

	// Wait for periodic flush
	time.Sleep(150 * time.Millisecond)

	w.mu.Lock()
	flushed := w.flushed
	w.mu.Unlock()

	if flushed < 1 {
		t.Errorf("flushed = %d, want >= 1 (interval flush)", flushed)
	}
}

