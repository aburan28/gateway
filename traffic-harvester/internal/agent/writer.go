package agent

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/traffic-harvester/traffic-harvester/internal/storage"
)

const (
	defaultBatchSize     = 100
	defaultFlushInterval = 5 * time.Second
)

// BufferedWriter batches CapturedRequests and periodically flushes them to a
// storage.Writer. It supports graceful shutdown via Close().
type BufferedWriter struct {
	writer        storage.Writer
	batchSize     int
	flushInterval time.Duration
	log           *slog.Logger

	mu      sync.Mutex
	pending int
	closed  bool

	// background flush
	cancel context.CancelFunc
	done   chan struct{}
}

// BufferedWriterConfig configures a BufferedWriter.
type BufferedWriterConfig struct {
	Writer        storage.Writer
	BatchSize     int
	FlushInterval time.Duration
	Logger        *slog.Logger
}

// NewBufferedWriter creates a BufferedWriter that batches writes and flushes
// to the underlying storage.Writer on batch size or interval, whichever comes first.
func NewBufferedWriter(cfg BufferedWriterConfig) *BufferedWriter {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultBatchSize
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = defaultFlushInterval
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())
	bw := &BufferedWriter{
		writer:        cfg.Writer,
		batchSize:     cfg.BatchSize,
		flushInterval: cfg.FlushInterval,
		log:           cfg.Logger,
		cancel:        cancel,
		done:          make(chan struct{}),
	}

	go bw.flushLoop(ctx)
	return bw
}

// Write sends a captured request to the underlying writer. If the batch size
// threshold is reached, a flush is triggered immediately.
func (bw *BufferedWriter) Write(ctx context.Context, req *storage.CapturedRequest) error {
	bw.mu.Lock()
	if bw.closed {
		bw.mu.Unlock()
		return storage.ErrWriterClosed
	}
	bw.mu.Unlock()

	if err := bw.writer.Write(ctx, req); err != nil {
		return err
	}

	bw.mu.Lock()
	bw.pending++
	shouldFlush := bw.pending >= bw.batchSize
	bw.mu.Unlock()

	if shouldFlush {
		return bw.Flush(ctx)
	}
	return nil
}

// Flush forces a flush of buffered data to the underlying writer.
func (bw *BufferedWriter) Flush(ctx context.Context) error {
	bw.mu.Lock()
	bw.pending = 0
	bw.mu.Unlock()

	return bw.writer.Flush(ctx)
}

// Close gracefully shuts down the writer, flushing any remaining data.
func (bw *BufferedWriter) Close() error {
	bw.cancel()
	<-bw.done

	bw.mu.Lock()
	bw.closed = true
	bw.mu.Unlock()

	if err := bw.writer.Flush(context.Background()); err != nil {
		bw.log.Error("failed to flush on close", "error", err)
	}
	return bw.writer.Close()
}

func (bw *BufferedWriter) flushLoop(ctx context.Context) {
	defer close(bw.done)
	ticker := time.NewTicker(bw.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			bw.mu.Lock()
			hasPending := bw.pending > 0
			bw.mu.Unlock()

			if hasPending {
				if err := bw.Flush(ctx); err != nil {
					bw.log.Warn("periodic flush failed", "error", err)
				}
			}
		}
	}
}

