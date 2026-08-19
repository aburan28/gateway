package agent

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/traffic-harvester/traffic-harvester/internal/storage"
)

// mockWriter is a test double for storage.Writer.
type mockWriter struct {
	mu       sync.Mutex
	requests []*storage.CapturedRequest
	flushed  int
	closed   bool
	writeErr error
	flushErr error
}

func (m *mockWriter) Write(_ context.Context, req *storage.CapturedRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.writeErr != nil {
		return m.writeErr
	}
	m.requests = append(m.requests, req)
	return nil
}

func (m *mockWriter) Flush(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.flushErr != nil {
		return m.flushErr
	}
	m.flushed++
	return nil
}

func (m *mockWriter) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockWriter) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.requests)
}

// --- Handler tests ---

func TestCaptureHandler_Handle(t *testing.T) {
	w := &mockWriter{}
	h := NewCaptureHandler(CaptureHandlerConfig{
		Writer:       w,
		MaxBodyBytes: 1024,
	})

	req := &CapturedHTTPRequest{
		Method:   "GET",
		Path:     "/api/test",
		Headers:  map[string][]string{"X-Test": {"value"}},
		Body:     strings.NewReader("hello world"),
		Protocol: "HTTP",
	}

	err := h.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if w.Len() != 1 {
		t.Fatalf("expected 1 captured request, got %d", w.Len())
	}

	captured := w.requests[0]
	if captured.Method != "GET" {
		t.Errorf("method = %q, want GET", captured.Method)
	}
	if captured.Path != "/api/test" {
		t.Errorf("path = %q, want /api/test", captured.Path)
	}
	if string(captured.Body) != "hello world" {
		t.Errorf("body = %q, want 'hello world'", captured.Body)
	}
}

func TestCaptureHandler_TruncatesBody(t *testing.T) {
	w := &mockWriter{}
	h := NewCaptureHandler(CaptureHandlerConfig{
		Writer:       w,
		MaxBodyBytes: 5,
	})

	req := &CapturedHTTPRequest{
		Method:   "POST",
		Path:     "/data",
		Body:     strings.NewReader("0123456789"),
		Protocol: "HTTP",
	}

	if err := h.Handle(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	captured := w.requests[0]
	if len(captured.Body) != 5 {
		t.Errorf("body length = %d, want 5", len(captured.Body))
	}
	if captured.Metadata["bodyTruncated"] != "true" {
		t.Error("expected bodyTruncated metadata")
	}
}

func TestCaptureHandler_WriteError(t *testing.T) {
	w := &mockWriter{writeErr: fmt.Errorf("disk full")}
	h := NewCaptureHandler(CaptureHandlerConfig{Writer: w})

	req := &CapturedHTTPRequest{
		Method: "GET", Path: "/fail",
		Body: strings.NewReader("x"), Protocol: "HTTP",
	}

	err := h.Handle(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}

	total, dropped, _ := h.Metrics()
	if total != 1 || dropped != 1 {
		t.Errorf("metrics: total=%d dropped=%d, want 1,1", total, dropped)
	}
}

func TestCaptureHandler_Metrics(t *testing.T) {
	w := &mockWriter{}
	h := NewCaptureHandler(CaptureHandlerConfig{Writer: w})

	for i := 0; i < 3; i++ {
		_ = h.Handle(context.Background(), &CapturedHTTPRequest{
			Method: "GET", Path: "/", Body: strings.NewReader("abc"), Protocol: "HTTP",
		})
	}

	total, dropped, bytesRecv := h.Metrics()
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
	if dropped != 0 {
		t.Errorf("dropped = %d, want 0", dropped)
	}
	if bytesRecv != 9 { // 3 * len("abc")
		t.Errorf("bytesRecv = %d, want 9", bytesRecv)
	}
}

