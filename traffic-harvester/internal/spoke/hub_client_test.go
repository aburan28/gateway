package spoke

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	hubv1 "github.com/traffic-harvester/traffic-harvester/proto/hub/v1"
	"google.golang.org/grpc"
)

// mockHubServer implements the HubServiceServer for testing.
type mockHubServer struct {
	hubv1.UnimplementedHubServiceServer

	mu                sync.Mutex
	registerCalls     int
	heartbeatCalls    int
	deregisterCalls   int
	reportStatusCalls int
	lastSpokeID       string
	lastStatuses      []*hubv1.CaptureStatusSummary
}

func (m *mockHubServer) RegisterSpoke(_ context.Context, req *hubv1.RegisterSpokeRequest) (*hubv1.RegisterSpokeResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registerCalls++
	m.lastSpokeID = req.SpokeId
	return &hubv1.RegisterSpokeResponse{
		Accepted:                 true,
		Message:                  "registered",
		HeartbeatIntervalSeconds: 5,
	}, nil
}

func (m *mockHubServer) Heartbeat(_ context.Context, req *hubv1.HeartbeatRequest) (*hubv1.HeartbeatResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.heartbeatCalls++
	m.lastSpokeID = req.SpokeId
	return &hubv1.HeartbeatResponse{Acknowledged: true}, nil
}

func (m *mockHubServer) DeregisterSpoke(_ context.Context, req *hubv1.DeregisterSpokeRequest) (*hubv1.DeregisterSpokeResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deregisterCalls++
	m.lastSpokeID = req.SpokeId
	return &hubv1.DeregisterSpokeResponse{Acknowledged: true}, nil
}

func (m *mockHubServer) ReportCaptureStatus(_ context.Context, req *hubv1.ReportCaptureStatusRequest) (*hubv1.ReportCaptureStatusResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reportStatusCalls++
	m.lastSpokeID = req.SpokeId
	m.lastStatuses = req.Statuses
	return &hubv1.ReportCaptureStatusResponse{Acknowledged: true}, nil
}

// startMockServer starts a mock gRPC server and returns its address and cleanup.
func startMockServer(t *testing.T, mock *mockHubServer) (string, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	srv := grpc.NewServer()
	hubv1.RegisterHubServiceServer(srv, mock)
	go func() {
		if err := srv.Serve(lis); err != nil {
			// Server stopped
		}
	}()

	return lis.Addr().String(), func() {
		srv.GracefulStop()
	}
}

func newTestClient(t *testing.T, addr string) *HubClient {
	t.Helper()
	return NewHubClient(HubClientConfig{
		HubAddress: addr,
		SpokeName:  "test-spoke",
		ClusterID:  "test-cluster",
		Logger:     logr.Discard(),
	})
}

func TestHubClient_ConnectAndRegister(t *testing.T) {
	mock := &mockHubServer{}
	addr, cleanup := startMockServer(t, mock)
	defer cleanup()

	client := newTestClient(t, addr)
	ctx := context.Background()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	heartbeatSec, err := client.Register(ctx)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if heartbeatSec != 5 {
		t.Errorf("expected heartbeat interval 5, got %d", heartbeatSec)
	}

	mock.mu.Lock()
	if mock.registerCalls != 1 {
		t.Errorf("expected 1 register call, got %d", mock.registerCalls)
	}
	if mock.lastSpokeID != "test-spoke" {
		t.Errorf("expected spokeID 'test-spoke', got %q", mock.lastSpokeID)
	}
	mock.mu.Unlock()

	if !client.IsConnected() {
		t.Error("expected client to be connected")
	}
}

func TestHubClient_ReportStatus(t *testing.T) {
	mock := &mockHubServer{}
	addr, cleanup := startMockServer(t, mock)
	defer cleanup()

	client := newTestClient(t, addr)
	ctx := context.Background()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	if _, err := client.Register(ctx); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	statuses := []*hubv1.CaptureStatusSummary{{
		CaptureName:      "test-capture",
		CaptureNamespace: "default",
		Phase:            hubv1.CapturePhase_CAPTURE_PHASE_ACTIVE,
		CapturedRequests: 100,
		ReadyReplicas:    3,
		DesiredReplicas:  3,
	}}

	if err := client.ReportStatus(ctx, statuses); err != nil {
		t.Fatalf("ReportStatus failed: %v", err)
	}

	mock.mu.Lock()
	if mock.reportStatusCalls != 1 {
		t.Errorf("expected 1 report call, got %d", mock.reportStatusCalls)
	}
	if len(mock.lastStatuses) != 1 {
		t.Errorf("expected 1 status, got %d", len(mock.lastStatuses))
	} else if mock.lastStatuses[0].CaptureName != "test-capture" {
		t.Errorf("expected capture name 'test-capture', got %q", mock.lastStatuses[0].CaptureName)
	}
	mock.mu.Unlock()
}

func TestHubClient_Heartbeat(t *testing.T) {
	mock := &mockHubServer{}
	addr, cleanup := startMockServer(t, mock)
	defer cleanup()

	client := newTestClient(t, addr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	if _, err := client.Register(ctx); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Start heartbeat with a very short interval
	client.StartHeartbeat(ctx, 100*time.Millisecond)

	// Wait for at least 2 heartbeats
	time.Sleep(350 * time.Millisecond)

	mock.mu.Lock()
	calls := mock.heartbeatCalls
	mock.mu.Unlock()

	if calls < 2 {
		t.Errorf("expected at least 2 heartbeat calls, got %d", calls)
	}
}

func TestHubClient_Deregister(t *testing.T) {
	mock := &mockHubServer{}
	addr, cleanup := startMockServer(t, mock)
	defer cleanup()

	client := newTestClient(t, addr)
	ctx := context.Background()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	if _, err := client.Register(ctx); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if err := client.Deregister(ctx); err != nil {
		t.Fatalf("Deregister failed: %v", err)
	}

	mock.mu.Lock()
	if mock.deregisterCalls != 1 {
		t.Errorf("expected 1 deregister call, got %d", mock.deregisterCalls)
	}
	mock.mu.Unlock()
}

func TestHubClient_StandaloneMode(t *testing.T) {
	// When not connected, operations should return appropriate errors
	client := NewHubClient(HubClientConfig{
		HubAddress: "localhost:0",
		SpokeName:  "standalone-spoke",
		ClusterID:  "test",
		Logger:     logr.Discard(),
	})

	ctx := context.Background()

	// ReportStatus should fail when not connected
	err := client.ReportStatus(ctx, nil)
	if err == nil {
		t.Error("expected error for ReportStatus when not connected")
	}

	// Deregister should be a no-op when not connected
	err = client.Deregister(ctx)
	if err != nil {
		t.Errorf("expected no error for Deregister when not connected, got %v", err)
	}

	if client.IsConnected() {
		t.Error("expected client to not be connected")
	}
}

func TestHubClient_Close(t *testing.T) {
	mock := &mockHubServer{}
	addr, cleanup := startMockServer(t, mock)
	defer cleanup()

	client := newTestClient(t, addr)
	ctx := context.Background()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	if !client.IsConnected() {
		t.Error("expected connected after Connect")
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if client.IsConnected() {
		t.Error("expected not connected after Close")
	}
}
