package agent

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleHTTP_CapturesRequest(t *testing.T) {
	w := &mockWriter{}
	handler := NewCaptureHandler(CaptureHandlerConfig{Writer: w, MaxBodyBytes: 1 << 20})

	srv := NewAgentServer(AgentServerConfig{Handler: handler})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/resource", strings.NewReader(`{"key":"value"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "test-123")

	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	if w.Len() != 1 {
		t.Fatalf("captured %d requests, want 1", w.Len())
	}

	captured := w.requests[0]
	if captured.Method != "POST" {
		t.Errorf("method = %q, want POST", captured.Method)
	}
	if captured.Path != "/api/v1/resource" {
		t.Errorf("path = %q, want /api/v1/resource", captured.Path)
	}
	if captured.Protocol != "HTTP" {
		t.Errorf("protocol = %q, want HTTP", captured.Protocol)
	}
	if string(captured.Body) != `{"key":"value"}` {
		t.Errorf("body = %q, want JSON", captured.Body)
	}
}

func TestHandleHTTP_AllMethods(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			w := &mockWriter{}
			handler := NewCaptureHandler(CaptureHandlerConfig{Writer: w})
			srv := NewAgentServer(AgentServerConfig{Handler: handler})

			req := httptest.NewRequest(method, "/test", nil)
			rec := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
			}
		})
	}
}

func TestHealthEndpoint(t *testing.T) {
	w := &mockWriter{}
	handler := NewCaptureHandler(CaptureHandlerConfig{Writer: w})
	srv := NewAgentServer(AgentServerConfig{Handler: handler})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.healthServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "ok") {
		t.Errorf("body = %q, want to contain 'ok'", body)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	w := &mockWriter{}
	handler := NewCaptureHandler(CaptureHandlerConfig{Writer: w})
	srv := NewAgentServer(AgentServerConfig{Handler: handler})

	// Capture a request first
	httpReq := httptest.NewRequest(http.MethodGet, "/api/test", strings.NewReader("data"))
	httpRec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(httpRec, httpReq)

	// Check metrics
	metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsRec := httptest.NewRecorder()
	srv.healthServer.Handler.ServeHTTP(metricsRec, metricsReq)

	body, _ := io.ReadAll(metricsRec.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "capture_agent_requests_total 1") {
		t.Errorf("metrics missing requests_total 1, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "capture_agent_bytes_received_total 4") {
		t.Errorf("metrics missing bytes_received_total 4, got:\n%s", bodyStr)
	}
}

func TestHandleHTTP_WriteError(t *testing.T) {
	w := &mockWriter{writeErr: io.ErrUnexpectedEOF}
	handler := NewCaptureHandler(CaptureHandlerConfig{Writer: w})
	srv := NewAgentServer(AgentServerConfig{Handler: handler})

	req := httptest.NewRequest(http.MethodGet, "/fail", strings.NewReader("x"))
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

