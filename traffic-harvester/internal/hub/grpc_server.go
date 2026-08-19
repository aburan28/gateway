// Package hub implements the hub controller and gRPC server that provides
// global orchestration and visibility across spoke clusters.
package hub

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	hubv1 "github.com/traffic-harvester/traffic-harvester/proto/hub/v1"
)

const (
	// DefaultHeartbeatInterval is sent to spokes on registration.
	DefaultHeartbeatInterval = 30
	// SpokeTimeout is how long after the last heartbeat a spoke is considered disconnected.
	SpokeTimeout = 90 * time.Second
)

// spokeEntry tracks a connected spoke in the in-memory registry.
type spokeEntry struct {
	info          *hubv1.SpokeInfo
	lastHeartbeat time.Time
	captures      map[string]*hubv1.CaptureStatusSummary // key: "namespace/name"
}

// Server implements hubv1.HubServiceServer and manages spoke registration,
// heartbeats, and aggregated capture status.
type Server struct {
	hubv1.UnimplementedHubServiceServer

	mu     sync.RWMutex
	spokes map[string]*spokeEntry // key: spoke_id

	grpcServer *grpc.Server
	address    string
}

// NewServer creates a new hub gRPC server.
func NewServer(address string, opts ...grpc.ServerOption) *Server {
	s := &Server{
		spokes:  make(map[string]*spokeEntry),
		address: address,
	}
	s.grpcServer = grpc.NewServer(opts...)
	hubv1.RegisterHubServiceServer(s.grpcServer, s)
	return s
}

// NewServerWithTLS creates a new hub gRPC server with TLS credentials.
func NewServerWithTLS(address string, creds credentials.TransportCredentials) *Server {
	return NewServer(address, grpc.Creds(creds))
}

// Start begins serving gRPC requests. It blocks until the server is stopped.
func (s *Server) Start(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.address, err)
	}

	// Shut down gracefully when context is cancelled.
	go func() {
		<-ctx.Done()
		s.grpcServer.GracefulStop()
	}()

	return s.grpcServer.Serve(lis)
}

// Stop gracefully stops the gRPC server.
func (s *Server) Stop() {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
}

// GRPCServer returns the underlying grpc.Server for testing or additional configuration.
func (s *Server) GRPCServer() *grpc.Server {
	return s.grpcServer
}

// --- Spoke lifecycle RPCs ---

// RegisterSpoke registers a spoke cluster with the hub.
func (s *Server) RegisterSpoke(_ context.Context, req *hubv1.RegisterSpokeRequest) (*hubv1.RegisterSpokeResponse, error) {
	if req.GetSpokeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "spoke_id is required")
	}

	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	s.spokes[req.SpokeId] = &spokeEntry{
		info: &hubv1.SpokeInfo{
			SpokeId:        req.SpokeId,
			ClusterName:    req.ClusterName,
			ActiveCaptures: 0,
			LastHeartbeat:  timestamppb.New(now),
			Capabilities:   req.Capabilities,
			State:          hubv1.SpokeState_SPOKE_STATE_CONNECTED,
		},
		lastHeartbeat: now,
		captures:      make(map[string]*hubv1.CaptureStatusSummary),
	}

	return &hubv1.RegisterSpokeResponse{
		Accepted:                 true,
		Message:                  "spoke registered",
		HeartbeatIntervalSeconds: DefaultHeartbeatInterval,
	}, nil
}

// Heartbeat updates the last-seen timestamp for a spoke.
func (s *Server) Heartbeat(_ context.Context, req *hubv1.HeartbeatRequest) (*hubv1.HeartbeatResponse, error) {
	if req.GetSpokeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "spoke_id is required")
	}

	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.spokes[req.SpokeId]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "spoke %q not registered", req.SpokeId)
	}

	entry.lastHeartbeat = now
	entry.info.LastHeartbeat = timestamppb.New(now)
	entry.info.ActiveCaptures = req.ActiveCaptures
	entry.info.State = hubv1.SpokeState_SPOKE_STATE_CONNECTED

	// Update capture summaries from heartbeat.
	for _, cs := range req.CaptureSummaries {
		key := captureKey(cs.CaptureNamespace, cs.CaptureName)
		entry.captures[key] = cs
	}

	return &hubv1.HeartbeatResponse{Acknowledged: true}, nil
}

// DeregisterSpoke removes a spoke from the registry.
func (s *Server) DeregisterSpoke(_ context.Context, req *hubv1.DeregisterSpokeRequest) (*hubv1.DeregisterSpokeResponse, error) {
	if req.GetSpokeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "spoke_id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.spokes[req.SpokeId]; !ok {
		return nil, status.Errorf(codes.NotFound, "spoke %q not registered", req.SpokeId)
	}

	delete(s.spokes, req.SpokeId)
	return &hubv1.DeregisterSpokeResponse{Acknowledged: true}, nil
}

// WatchDirectives is a server-streaming RPC for hub-initiated capture commands.
// Currently a no-op that keeps the stream open until the client disconnects.
func (s *Server) WatchDirectives(req *hubv1.WatchDirectivesRequest, stream grpc.ServerStreamingServer[hubv1.WatchDirectivesResponse]) error {
	if req.GetSpokeId() == "" {
		return status.Error(codes.InvalidArgument, "spoke_id is required")
	}

	s.mu.RLock()
	_, ok := s.spokes[req.SpokeId]
	s.mu.RUnlock()
	if !ok {
		return status.Errorf(codes.NotFound, "spoke %q not registered", req.SpokeId)
	}

	// Block until context is done (client disconnects or server shuts down).
	<-stream.Context().Done()
	return stream.Context().Err()
}

// --- Status reporting ---

// ReportCaptureStatus receives capture status updates from a spoke.
func (s *Server) ReportCaptureStatus(_ context.Context, req *hubv1.ReportCaptureStatusRequest) (*hubv1.ReportCaptureStatusResponse, error) {
	if req.GetSpokeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "spoke_id is required")
	}
	if len(req.GetStatuses()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one status is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.spokes[req.SpokeId]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "spoke %q not registered", req.SpokeId)
	}

	for _, cs := range req.Statuses {
		key := captureKey(cs.CaptureNamespace, cs.CaptureName)
		entry.captures[key] = cs
	}
	entry.info.ActiveCaptures = int32(len(entry.captures))

	return &hubv1.ReportCaptureStatusResponse{Acknowledged: true}, nil
}

// --- Query RPCs ---

// ListCaptures returns all captures across spokes, optionally filtered by spoke_id.
func (s *Server) ListCaptures(_ context.Context, req *hubv1.ListCapturesRequest) (*hubv1.ListCapturesResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var captures []*hubv1.CaptureInfo
	for spokeID, entry := range s.spokes {
		if req.GetSpokeId() != "" && spokeID != req.SpokeId {
			continue
		}
		for _, cs := range entry.captures {
			if req.GetNamespace() != "" && cs.CaptureNamespace != req.Namespace {
				continue
			}
			captures = append(captures, captureInfoFromSummary(cs, spokeID))
		}
	}

	return &hubv1.ListCapturesResponse{Captures: captures}, nil
}

// GetCaptureStatus returns the status of a specific capture.
func (s *Server) GetCaptureStatus(_ context.Context, req *hubv1.GetCaptureStatusRequest) (*hubv1.GetCaptureStatusResponse, error) {
	if req.GetCaptureName() == "" || req.GetCaptureNamespace() == "" {
		return nil, status.Error(codes.InvalidArgument, "capture_name and capture_namespace are required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	key := captureKey(req.CaptureNamespace, req.CaptureName)

	// If spoke_id is given, look up directly.
	if req.GetSpokeId() != "" {
		entry, ok := s.spokes[req.SpokeId]
		if !ok {
			return nil, status.Errorf(codes.NotFound, "spoke %q not registered", req.SpokeId)
		}
		cs, ok := entry.captures[key]
		if !ok {
			return nil, status.Errorf(codes.NotFound, "capture %q not found on spoke %q", key, req.SpokeId)
		}
		return &hubv1.GetCaptureStatusResponse{
			Capture: captureInfoFromSummary(cs, req.SpokeId),
		}, nil
	}

	// Search all spokes for the capture.
	for spokeID, entry := range s.spokes {
		if cs, ok := entry.captures[key]; ok {
			return &hubv1.GetCaptureStatusResponse{
				Capture: captureInfoFromSummary(cs, spokeID),
			}, nil
		}
	}

	return nil, status.Errorf(codes.NotFound, "capture %q not found", key)
}

// ListSpokes returns information about all registered spokes.
func (s *Server) ListSpokes(_ context.Context, _ *hubv1.ListSpokesRequest) (*hubv1.ListSpokesResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	spokes := make([]*hubv1.SpokeInfo, 0, len(s.spokes))
	now := time.Now()
	for _, entry := range s.spokes {
		info := cloneSpokeInfo(entry.info)
		// Mark disconnected if heartbeat is stale.
		if now.Sub(entry.lastHeartbeat) > SpokeTimeout {
			info.State = hubv1.SpokeState_SPOKE_STATE_DISCONNECTED
		}
		spokes = append(spokes, info)
	}

	return &hubv1.ListSpokesResponse{Spokes: spokes}, nil
}

// --- Status aggregation helpers ---

// ConnectedSpokeCount returns the number of connected spokes.
func (s *Server) ConnectedSpokeCount() int32 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int32
	now := time.Now()
	for _, entry := range s.spokes {
		if now.Sub(entry.lastHeartbeat) <= SpokeTimeout {
			count++
		}
	}
	return count
}

// ActiveCaptureCount returns the total number of active captures across all spokes.
func (s *Server) ActiveCaptureCount() int32 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int32
	for _, entry := range s.spokes {
		count += int32(len(entry.captures))
	}
	return count
}

// SpokeStatuses returns a snapshot of spoke statuses for the CaptureHub CR status.
func (s *Server) SpokeStatuses() []SpokeStatusSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]SpokeStatusSnapshot, 0, len(s.spokes))
	for _, entry := range s.spokes {
		result = append(result, SpokeStatusSnapshot{
			Name:           entry.info.ClusterName,
			LastHeartbeat:  entry.lastHeartbeat,
			ActiveCaptures: entry.info.ActiveCaptures,
		})
	}
	return result
}

// SpokeStatusSnapshot is a plain Go struct used by the controller to update
// CaptureHub CR status without importing proto types.
type SpokeStatusSnapshot struct {
	Name           string
	LastHeartbeat  time.Time
	ActiveCaptures int32
}

// --- Helpers ---

func captureKey(namespace, name string) string {
	return namespace + "/" + name
}

func captureInfoFromSummary(cs *hubv1.CaptureStatusSummary, spokeID string) *hubv1.CaptureInfo {
	return &hubv1.CaptureInfo{
		CaptureName:      cs.CaptureName,
		CaptureNamespace: cs.CaptureNamespace,
		SpokeId:          spokeID,
		Phase:            cs.Phase,
		CapturedRequests: cs.CapturedRequests,
		BytesWritten:     cs.BytesWritten,
	}
}

func cloneSpokeInfo(info *hubv1.SpokeInfo) *hubv1.SpokeInfo {
	return &hubv1.SpokeInfo{
		SpokeId:        info.SpokeId,
		ClusterName:    info.ClusterName,
		ActiveCaptures: info.ActiveCaptures,
		LastHeartbeat:  info.LastHeartbeat,
		Capabilities:   info.Capabilities,
		State:          info.State,
	}
}
