// Package agent implements the capture agent that receives mirrored traffic
// and writes captured request data to pluggable storage backends.
package agent

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/traffic-harvester/traffic-harvester/internal/storage"
)

// CapturedHTTPRequest holds the raw data extracted from an incoming mirrored request.
type CapturedHTTPRequest struct {
	Method   string
	Path     string
	Headers  map[string][]string
	Body     io.Reader
	Protocol string
	Metadata map[string]string
}

// CaptureHandler receives captured requests, enforces limits, and sends them to a writer.
type CaptureHandler struct {
	writer       storage.Writer
	maxBodyBytes int64
	log          *slog.Logger

	// Metrics
	requestsTotal   atomic.Int64
	requestsDropped atomic.Int64
	bytesReceived   atomic.Int64
}

// CaptureHandlerConfig configures a CaptureHandler.
type CaptureHandlerConfig struct {
	Writer       storage.Writer
	MaxBodyBytes int64
	Logger       *slog.Logger
}

// NewCaptureHandler creates a CaptureHandler with the given configuration.
func NewCaptureHandler(cfg CaptureHandlerConfig) *CaptureHandler {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20 // 1MB default
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &CaptureHandler{
		writer:       cfg.Writer,
		maxBodyBytes: cfg.MaxBodyBytes,
		log:          cfg.Logger,
	}
}

// Handle processes a single captured request. It enforces the max body size,
// converts to a CapturedRequest, and writes it to storage. If the write fails,
// the request is dropped and a metric counter is incremented.
func (h *CaptureHandler) Handle(ctx context.Context, req *CapturedHTTPRequest) error {
	h.requestsTotal.Add(1)

	body, err := io.ReadAll(io.LimitReader(req.Body, h.maxBodyBytes+1))
	if err != nil {
		h.requestsDropped.Add(1)
		h.log.Warn("failed to read request body", "error", err)
		return err
	}

	truncated := int64(len(body)) > h.maxBodyBytes
	if truncated {
		body = body[:h.maxBodyBytes]
	}

	h.bytesReceived.Add(int64(len(body)))

	captured := &storage.CapturedRequest{
		ID:            uuid.New().String(),
		Timestamp:     time.Now().UTC(),
		Method:        req.Method,
		Path:          req.Path,
		Headers:       req.Headers,
		Body:          body,
		ContentLength: int64(len(body)),
		Protocol:      req.Protocol,
		Metadata:      req.Metadata,
	}

	if truncated {
		if captured.Metadata == nil {
			captured.Metadata = make(map[string]string)
		}
		captured.Metadata["bodyTruncated"] = "true"
	}

	if err := h.writer.Write(ctx, captured); err != nil {
		h.requestsDropped.Add(1)
		h.log.Warn("failed to write captured request, dropping", "error", err, "path", req.Path)
		return err
	}

	return nil
}

// Metrics returns current handler metrics.
func (h *CaptureHandler) Metrics() (total, dropped, bytesRecv int64) {
	return h.requestsTotal.Load(), h.requestsDropped.Load(), h.bytesReceived.Load()
}

