package hub

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	hubv1 "github.com/traffic-harvester/traffic-harvester/proto/hub/v1"
)

func newTestServer() *Server {
	return NewServer(":0") // port 0 = OS-assigned
}

func TestRegisterSpoke(t *testing.T) {
	srv := newTestServer()
	ctx := context.Background()

	resp, err := srv.RegisterSpoke(ctx, &hubv1.RegisterSpokeRequest{
		SpokeId:     "spoke-1",
		ClusterName: "cluster-a",
	})
	if err != nil {
		t.Fatalf("RegisterSpoke failed: %v", err)
	}
	if !resp.Accepted {
		t.Fatal("expected spoke to be accepted")
	}
	if resp.HeartbeatIntervalSeconds != DefaultHeartbeatInterval {
		t.Errorf("heartbeat interval = %d, want %d", resp.HeartbeatIntervalSeconds, DefaultHeartbeatInterval)
	}

	// Verify spoke appears in registry.
	if srv.ConnectedSpokeCount() != 1 {
		t.Errorf("connected spokes = %d, want 1", srv.ConnectedSpokeCount())
	}
}

func TestRegisterSpoke_MissingID(t *testing.T) {
	srv := newTestServer()
	_, err := srv.RegisterSpoke(context.Background(), &hubv1.RegisterSpokeRequest{})
	if s, ok := status.FromError(err); !ok || s.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
}

func TestHeartbeat(t *testing.T) {
	srv := newTestServer()
	ctx := context.Background()

	// Register first.
	_, _ = srv.RegisterSpoke(ctx, &hubv1.RegisterSpokeRequest{SpokeId: "spoke-1", ClusterName: "c"})

	resp, err := srv.Heartbeat(ctx, &hubv1.HeartbeatRequest{
		SpokeId:        "spoke-1",
		ActiveCaptures: 5,
		CaptureSummaries: []*hubv1.CaptureStatusSummary{
			{CaptureName: "cap-1", CaptureNamespace: "ns-1", Phase: hubv1.CapturePhase_CAPTURE_PHASE_ACTIVE, CapturedRequests: 100},
		},
	})
	if err != nil {
		t.Fatalf("Heartbeat failed: %v", err)
	}
	if !resp.Acknowledged {
		t.Fatal("expected heartbeat acknowledged")
	}

	// Verify capture was recorded.
	listResp, _ := srv.ListCaptures(ctx, &hubv1.ListCapturesRequest{})
	if len(listResp.Captures) != 1 {
		t.Fatalf("captures = %d, want 1", len(listResp.Captures))
	}
	if listResp.Captures[0].CapturedRequests != 100 {
		t.Errorf("captured requests = %d, want 100", listResp.Captures[0].CapturedRequests)
	}
}

func TestHeartbeat_UnregisteredSpoke(t *testing.T) {
	srv := newTestServer()
	_, err := srv.Heartbeat(context.Background(), &hubv1.HeartbeatRequest{SpokeId: "unknown"})
	if s, ok := status.FromError(err); !ok || s.Code() != codes.NotFound {
		t.Errorf("expected NotFound, got %v", err)
	}
}

func TestDeregisterSpoke(t *testing.T) {
	srv := newTestServer()
	ctx := context.Background()

	_, _ = srv.RegisterSpoke(ctx, &hubv1.RegisterSpokeRequest{SpokeId: "spoke-1", ClusterName: "c"})

	resp, err := srv.DeregisterSpoke(ctx, &hubv1.DeregisterSpokeRequest{SpokeId: "spoke-1"})
	if err != nil {
		t.Fatalf("DeregisterSpoke failed: %v", err)
	}
	if !resp.Acknowledged {
		t.Fatal("expected acknowledged")
	}
	if srv.ConnectedSpokeCount() != 0 {
		t.Errorf("connected spokes = %d, want 0", srv.ConnectedSpokeCount())
	}
}

func TestDeregisterSpoke_NotFound(t *testing.T) {
	srv := newTestServer()
	_, err := srv.DeregisterSpoke(context.Background(), &hubv1.DeregisterSpokeRequest{SpokeId: "nope"})
	if s, ok := status.FromError(err); !ok || s.Code() != codes.NotFound {
		t.Errorf("expected NotFound, got %v", err)
	}
}

func TestReportCaptureStatus(t *testing.T) {
	srv := newTestServer()
	ctx := context.Background()

	_, _ = srv.RegisterSpoke(ctx, &hubv1.RegisterSpokeRequest{SpokeId: "spoke-1", ClusterName: "c"})

	resp, err := srv.ReportCaptureStatus(ctx, &hubv1.ReportCaptureStatusRequest{
		SpokeId: "spoke-1",
		Statuses: []*hubv1.CaptureStatusSummary{
			{CaptureName: "cap-a", CaptureNamespace: "ns-1", Phase: hubv1.CapturePhase_CAPTURE_PHASE_ACTIVE, CapturedRequests: 42},
			{CaptureName: "cap-b", CaptureNamespace: "ns-1", Phase: hubv1.CapturePhase_CAPTURE_PHASE_PENDING},
		},
	})
	if err != nil {
		t.Fatalf("ReportCaptureStatus failed: %v", err)
	}
	if !resp.Acknowledged {
		t.Fatal("expected acknowledged")
	}

	if srv.ActiveCaptureCount() != 2 {
		t.Errorf("active captures = %d, want 2", srv.ActiveCaptureCount())
	}
}



func TestReportCaptureStatus_EmptyStatuses(t *testing.T) {
	srv := newTestServer()
	ctx := context.Background()
	_, _ = srv.RegisterSpoke(ctx, &hubv1.RegisterSpokeRequest{SpokeId: "spoke-1", ClusterName: "c"})

	_, err := srv.ReportCaptureStatus(ctx, &hubv1.ReportCaptureStatusRequest{
		SpokeId:  "spoke-1",
		Statuses: nil,
	})
	if s, ok := status.FromError(err); !ok || s.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
}

func TestListCaptures_FilterBySpoke(t *testing.T) {
	srv := newTestServer()
	ctx := context.Background()

	_, _ = srv.RegisterSpoke(ctx, &hubv1.RegisterSpokeRequest{SpokeId: "spoke-1", ClusterName: "c1"})
	_, _ = srv.RegisterSpoke(ctx, &hubv1.RegisterSpokeRequest{SpokeId: "spoke-2", ClusterName: "c2"})

	_, _ = srv.ReportCaptureStatus(ctx, &hubv1.ReportCaptureStatusRequest{
		SpokeId:  "spoke-1",
		Statuses: []*hubv1.CaptureStatusSummary{{CaptureName: "cap-1", CaptureNamespace: "ns"}},
	})
	_, _ = srv.ReportCaptureStatus(ctx, &hubv1.ReportCaptureStatusRequest{
		SpokeId:  "spoke-2",
		Statuses: []*hubv1.CaptureStatusSummary{{CaptureName: "cap-2", CaptureNamespace: "ns"}},
	})

	// List all.
	allResp, _ := srv.ListCaptures(ctx, &hubv1.ListCapturesRequest{})
	if len(allResp.Captures) != 2 {
		t.Errorf("all captures = %d, want 2", len(allResp.Captures))
	}

	// Filter by spoke.
	filteredResp, _ := srv.ListCaptures(ctx, &hubv1.ListCapturesRequest{SpokeId: "spoke-1"})
	if len(filteredResp.Captures) != 1 {
		t.Errorf("filtered captures = %d, want 1", len(filteredResp.Captures))
	}
}

func TestGetCaptureStatus(t *testing.T) {
	srv := newTestServer()
	ctx := context.Background()

	_, _ = srv.RegisterSpoke(ctx, &hubv1.RegisterSpokeRequest{SpokeId: "spoke-1", ClusterName: "c1"})
	_, _ = srv.ReportCaptureStatus(ctx, &hubv1.ReportCaptureStatusRequest{
		SpokeId: "spoke-1",
		Statuses: []*hubv1.CaptureStatusSummary{
			{CaptureName: "cap-1", CaptureNamespace: "ns-1", Phase: hubv1.CapturePhase_CAPTURE_PHASE_ACTIVE, CapturedRequests: 77},
		},
	})

	resp, err := srv.GetCaptureStatus(ctx, &hubv1.GetCaptureStatusRequest{
		CaptureName: "cap-1", CaptureNamespace: "ns-1",
	})
	if err != nil {
		t.Fatalf("GetCaptureStatus failed: %v", err)
	}
	if resp.Capture.CapturedRequests != 77 {
		t.Errorf("captured requests = %d, want 77", resp.Capture.CapturedRequests)
	}
}

func TestGetCaptureStatus_NotFound(t *testing.T) {
	srv := newTestServer()
	_, err := srv.GetCaptureStatus(context.Background(), &hubv1.GetCaptureStatusRequest{
		CaptureName: "missing", CaptureNamespace: "ns",
	})
	if s, ok := status.FromError(err); !ok || s.Code() != codes.NotFound {
		t.Errorf("expected NotFound, got %v", err)
	}
}

func TestListSpokes(t *testing.T) {
	srv := newTestServer()
	ctx := context.Background()

	_, _ = srv.RegisterSpoke(ctx, &hubv1.RegisterSpokeRequest{SpokeId: "spoke-1", ClusterName: "cluster-a"})
	_, _ = srv.RegisterSpoke(ctx, &hubv1.RegisterSpokeRequest{SpokeId: "spoke-2", ClusterName: "cluster-b"})

	resp, err := srv.ListSpokes(ctx, &hubv1.ListSpokesRequest{})
	if err != nil {
		t.Fatalf("ListSpokes failed: %v", err)
	}
	if len(resp.Spokes) != 2 {
		t.Errorf("spokes = %d, want 2", len(resp.Spokes))
	}

	// All should be connected (recent heartbeat).
	for _, sp := range resp.Spokes {
		if sp.State != hubv1.SpokeState_SPOKE_STATE_CONNECTED {
			t.Errorf("spoke %s should be connected, got %v", sp.SpokeId, sp.State)
		}
	}
}

func TestListSpokes_DisconnectedTimeout(t *testing.T) {
	srv := newTestServer()
	ctx := context.Background()

	_, _ = srv.RegisterSpoke(ctx, &hubv1.RegisterSpokeRequest{SpokeId: "spoke-1", ClusterName: "c"})

	// Manually backdate heartbeat to simulate timeout.
	srv.mu.Lock()
	srv.spokes["spoke-1"].lastHeartbeat = time.Now().Add(-2 * SpokeTimeout)
	srv.mu.Unlock()

	resp, _ := srv.ListSpokes(ctx, &hubv1.ListSpokesRequest{})
	if len(resp.Spokes) != 1 {
		t.Fatal("expected 1 spoke")
	}
	if resp.Spokes[0].State != hubv1.SpokeState_SPOKE_STATE_DISCONNECTED {
		t.Errorf("spoke should be disconnected after timeout, got %v", resp.Spokes[0].State)
	}
}

func TestSpokeStatuses(t *testing.T) {
	srv := newTestServer()
	ctx := context.Background()

	_, _ = srv.RegisterSpoke(ctx, &hubv1.RegisterSpokeRequest{SpokeId: "spoke-1", ClusterName: "cluster-a"})

	// Send a heartbeat with active captures count.
	_, _ = srv.Heartbeat(ctx, &hubv1.HeartbeatRequest{
		SpokeId:        "spoke-1",
		ActiveCaptures: 3,
	})

	snapshots := srv.SpokeStatuses()
	if len(snapshots) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snapshots))
	}
	if snapshots[0].Name != "cluster-a" {
		t.Errorf("name = %q, want %q", snapshots[0].Name, "cluster-a")
	}
	if snapshots[0].ActiveCaptures != 3 {
		t.Errorf("active captures = %d, want 3", snapshots[0].ActiveCaptures)
	}
}

func TestConnectedSpokeCount_ExcludesTimedOut(t *testing.T) {
	srv := newTestServer()
	ctx := context.Background()

	_, _ = srv.RegisterSpoke(ctx, &hubv1.RegisterSpokeRequest{SpokeId: "spoke-1", ClusterName: "c1"})
	_, _ = srv.RegisterSpoke(ctx, &hubv1.RegisterSpokeRequest{SpokeId: "spoke-2", ClusterName: "c2"})

	// Timeout spoke-2.
	srv.mu.Lock()
	srv.spokes["spoke-2"].lastHeartbeat = time.Now().Add(-2 * SpokeTimeout)
	srv.mu.Unlock()

	if count := srv.ConnectedSpokeCount(); count != 1 {
		t.Errorf("connected spokes = %d, want 1", count)
	}
}