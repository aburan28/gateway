package storage

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	defaultFlushInterval = 5 * time.Second
	defaultMaxBufferSize = 10 * 1024 * 1024
	dateLayout           = "2006-01-02"
	contentTypeJSONL     = "application/x-ndjson"
	contentEncodingGZIP  = "gzip"
)

var ErrWriterClosed = errors.New("storage writer is closed")

type CapturedRequest struct {
	ID            string              `json:"id"`
	Timestamp     time.Time           `json:"timestamp"`
	Method        string              `json:"method"`
	Path          string              `json:"path"`
	Headers       map[string][]string `json:"headers,omitempty"`
	Body          []byte              `json:"body,omitempty"`
	ContentLength int64               `json:"contentLength,omitempty"`
	Protocol      string              `json:"protocol"`
	Metadata      map[string]string   `json:"metadata,omitempty"`
}

type Writer interface {
	Write(ctx context.Context, req *CapturedRequest) error
	Flush(ctx context.Context) error
	Close() error
}

type WriterFactory interface {
	NewWriter(ctx context.Context, captureID string) (Writer, error)
}

type Config interface{ isStorageConfig() }

type objectUploader func(ctx context.Context, objectName string, payload []byte) error

type bufferedObjectWriter struct {
	mu             sync.Mutex
	captureID      string
	flushInterval  time.Duration
	maxBufferBytes int
	sequence       uint64
	buffer         bytes.Buffer
	closed         bool
	lastFlush      time.Time
	now            func() time.Time
	objectName     func(time.Time, uint64) string
	upload         objectUploader
}

func newBufferedObjectWriter(captureID string, flushInterval time.Duration, maxBufferBytes int, objectName func(time.Time, uint64) string, upload objectUploader) *bufferedObjectWriter {
	now := time.Now
	return &bufferedObjectWriter{
		captureID:      captureID,
		flushInterval:  normalizeFlushInterval(flushInterval),
		maxBufferBytes: normalizeMaxBufferBytes(maxBufferBytes),
		lastFlush:      now(),
		now:            now,
		objectName:     objectName,
		upload:         upload,
	}
}

func (w *bufferedObjectWriter) Write(ctx context.Context, req *CapturedRequest) error {
	line, err := marshalRequestLine(req)
	if err != nil {
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return ErrWriterClosed
	}

	if _, err := w.buffer.Write(line); err != nil {
		return err
	}

	if w.buffer.Len() >= w.maxBufferBytes || w.now().Sub(w.lastFlush) >= w.flushInterval {
		return w.flushLocked(ctx)
	}

	return nil
}

func (w *bufferedObjectWriter) Flush(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return ErrWriterClosed
	}

	return w.flushLocked(ctx)
}

func (w *bufferedObjectWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}

	if err := w.flushLocked(context.Background()); err != nil {
		return err
	}

	w.closed = true
	return nil
}

func (w *bufferedObjectWriter) flushLocked(ctx context.Context) error {
	if w.buffer.Len() == 0 {
		w.lastFlush = w.now()
		return nil
	}

	compressed, err := compressGZIP(w.buffer.Bytes())
	if err != nil {
		return err
	}

	objectName := w.objectName(w.now(), w.sequence+1)
	if err := w.upload(ctx, objectName, compressed); err != nil {
		return err
	}

	w.buffer.Reset()
	w.sequence++
	w.lastFlush = w.now()
	return nil
}

func marshalRequestLine(req *CapturedRequest) ([]byte, error) {
	if req == nil {
		return nil, errors.New("captured request cannot be nil")
	}

	line, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal captured request: %w", err)
	}

	return append(line, '\n'), nil
}

func compressGZIP(payload []byte) ([]byte, error) {
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	if _, err := gzipWriter.Write(payload); err != nil {
		return nil, fmt.Errorf("write gzip payload: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, fmt.Errorf("close gzip writer: %w", err)
	}
	return compressed.Bytes(), nil
}

func normalizeFlushInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return defaultFlushInterval
	}
	return interval
}

func normalizeMaxBufferBytes(size int) int {
	if size <= 0 {
		return defaultMaxBufferSize
	}
	return size
}

func newCloudObjectName(prefix, captureID, agentPod string) func(time.Time, uint64) string {
	prefix = strings.Trim(prefix, "/")
	return func(ts time.Time, seq uint64) string {
		parts := make([]string, 0, 4)
		if prefix != "" {
			parts = append(parts, prefix)
		}
		parts = append(parts, captureID, ts.UTC().Format(dateLayout), objectFileName(agentPod, seq))
		return path.Join(parts...)
	}
}

func newFilesystemObjectName(mountPath, captureID, agentPod string) func(time.Time, uint64) string {
	return func(ts time.Time, seq uint64) string {
		return filepath.Join(mountPath, captureID, ts.UTC().Format(dateLayout), objectFileName(agentPod, seq))
	}
}

func objectFileName(agentPod string, seq uint64) string {
	agentPod = strings.TrimSpace(agentPod)
	if agentPod == "" {
		agentPod = "unknown-agent"
	}
	return fmt.Sprintf("%s-%06d.jsonl.gz", agentPod, seq)
}
