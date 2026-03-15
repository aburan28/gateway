package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// AgentServerConfig holds configuration for the AgentServer.
type AgentServerConfig struct {
	HTTPPort   int
	GRPCPort   int
	HealthPort int
	Handler    *CaptureHandler
	Logger     *slog.Logger
}

// AgentServer hosts HTTP and gRPC sink servers that receive mirrored traffic,
// plus health and metrics endpoints.
type AgentServer struct {
	httpServer   *http.Server
	grpcServer   *grpc.Server
	healthServer *http.Server
	handler      *CaptureHandler
	log          *slog.Logger
	httpPort     int
	grpcPort     int
	healthPort   int
}

// NewAgentServer creates a new AgentServer.
func NewAgentServer(cfg AgentServerConfig) *AgentServer {
	if cfg.HTTPPort <= 0 {
		cfg.HTTPPort = 8080
	}
	if cfg.GRPCPort <= 0 {
		cfg.GRPCPort = 9090
	}
	if cfg.HealthPort <= 0 {
		cfg.HealthPort = 8081
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	s := &AgentServer{
		handler:    cfg.Handler,
		log:        cfg.Logger,
		httpPort:   cfg.HTTPPort,
		grpcPort:   cfg.GRPCPort,
		healthPort: cfg.HealthPort,
	}

	// HTTP sink
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/", s.handleHTTP)
	s.httpServer = &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:           httpMux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// gRPC sink with unknown service handler
	s.grpcServer = grpc.NewServer(
		grpc.UnknownServiceHandler(s.handleGRPC),
	)

	// Health + metrics
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/healthz", s.handleHealth)
	healthMux.HandleFunc("/metrics", s.handleMetrics)
	s.healthServer = &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.HealthPort),
		Handler:           healthMux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return s
}



// Start launches all servers and blocks until ctx is cancelled or an error occurs.
func (s *AgentServer) Start(ctx context.Context) error {
	errCh := make(chan error, 3)

	// gRPC listener
	grpcLis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.grpcPort))
	if err != nil {
		return fmt.Errorf("listen gRPC port %d: %w", s.grpcPort, err)
	}

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		s.log.Info("starting HTTP sink server", "port", s.httpPort)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("http server: %w", err)
		}
	}()

	go func() {
		defer wg.Done()
		s.log.Info("starting gRPC sink server", "port", s.grpcPort)
		if err := s.grpcServer.Serve(grpcLis); err != nil {
			errCh <- fmt.Errorf("grpc server: %w", err)
		}
	}()

	go func() {
		defer wg.Done()
		s.log.Info("starting health server", "port", s.healthPort)
		if err := s.healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("health server: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		return s.Shutdown()
	case err := <-errCh:
		_ = s.Shutdown()
		return err
	}
}

// Shutdown gracefully stops all servers.
func (s *AgentServer) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var errs []error
	s.grpcServer.GracefulStop()
	if err := s.httpServer.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("http shutdown: %w", err))
	}
	if err := s.healthServer.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("health shutdown: %w", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}
	return nil
}

// handleHTTP is the catch-all HTTP handler for mirrored requests.
func (s *AgentServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	captured := &CapturedHTTPRequest{
		Method:   r.Method,
		Path:     r.URL.Path,
		Headers:  r.Header,
		Body:     r.Body,
		Protocol: "HTTP",
		Metadata: map[string]string{
			"host":       r.Host,
			"remoteAddr": r.RemoteAddr,
			"query":      r.URL.RawQuery,
		},
	}

	if err := s.handler.Handle(r.Context(), captured); err != nil {
		s.log.Debug("capture failed", "error", err, "path", r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleGRPC is the grpc.UnknownServiceHandler that captures all mirrored gRPC calls.
func (s *AgentServer) handleGRPC(_ any, stream grpc.ServerStream) error {
	fullMethod, _ := grpc.MethodFromServerStream(stream)

	// Read the request message
	var msg rawMessage
	if err := stream.RecvMsg(&msg); err != nil && err != io.EOF {
		return status.Errorf(codes.Internal, "recv: %v", err)
	}

	// Extract gRPC metadata as headers
	headers := make(map[string][]string)
	if md, ok := metadata.FromIncomingContext(stream.Context()); ok {
		for k, v := range md {
			headers[k] = v
		}
	}

	captured := &CapturedHTTPRequest{
		Method:   "POST",
		Path:     fullMethod,
		Headers:  headers,
		Body:     bytes.NewReader(msg),
		Protocol: "gRPC",
		Metadata: map[string]string{
			"grpcMethod": fullMethod,
		},
	}

	if err := s.handler.Handle(stream.Context(), captured); err != nil {
		return status.Errorf(codes.Internal, "capture: %v", err)
	}
	return nil
}

// rawMessage implements the encoding interfaces for raw gRPC bytes.
type rawMessage []byte

func (r *rawMessage) Marshal() ([]byte, error) { return *r, nil }
func (r *rawMessage) Unmarshal(b []byte) error  { *r = b; return nil }
func (r *rawMessage) ProtoMessage()             {}
func (r *rawMessage) Reset()                    { *r = nil }
func (r *rawMessage) String() string            { return string(*r) }

// handleHealth serves health check endpoint.
func (s *AgentServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// handleMetrics serves Prometheus-style metrics.
func (s *AgentServer) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	total, dropped, bytesRecv := s.handler.Metrics()
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "# HELP capture_agent_requests_total Total captured requests\n")
	fmt.Fprintf(w, "# TYPE capture_agent_requests_total counter\n")
	fmt.Fprintf(w, "capture_agent_requests_total %d\n", total)
	fmt.Fprintf(w, "# HELP capture_agent_requests_dropped_total Dropped requests\n")
	fmt.Fprintf(w, "# TYPE capture_agent_requests_dropped_total counter\n")
	fmt.Fprintf(w, "capture_agent_requests_dropped_total %d\n", dropped)
	fmt.Fprintf(w, "# HELP capture_agent_bytes_received_total Bytes received\n")
	fmt.Fprintf(w, "# TYPE capture_agent_bytes_received_total counter\n")
	fmt.Fprintf(w, "capture_agent_bytes_received_total %d\n", bytesRecv)
}