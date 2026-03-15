package hub

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	capturev1alpha1 "github.com/traffic-harvester/traffic-harvester/api/v1alpha1"
)

// CaptureHubReconciler reconciles the singleton CaptureHub CR.
// It starts/stops the gRPC server based on the CaptureHub spec and
// updates the CR status with aggregated spoke information.
type CaptureHubReconciler struct {
	client.Client
	Log logr.Logger

	mu     sync.Mutex
	server *Server
	cancel context.CancelFunc
}

// SetupWithManager registers the reconciler with the controller-runtime manager.
func (r *CaptureHubReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&capturev1alpha1.CaptureHub{}).
		Complete(r)
}

// Reconcile handles CaptureHub CR changes: starts/reconfigures the gRPC server
// and updates the status with aggregated spoke data.
func (r *CaptureHubReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("capturehub", req.Name)

	var hub capturev1alpha1.CaptureHub
	if err := r.Get(ctx, req.NamespacedName, &hub); err != nil {
		if client.IgnoreNotFound(err) == nil {
			// CaptureHub deleted — stop the gRPC server.
			log.Info("CaptureHub deleted, stopping gRPC server")
			r.stopServer()
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Ensure the gRPC server is running with the configured address.
	if err := r.ensureServer(ctx, &hub); err != nil {
		log.Error(err, "failed to ensure gRPC server")
		return ctrl.Result{}, err
	}

	// Update CaptureHub status with aggregated spoke information.
	if err := r.updateStatus(ctx, &hub); err != nil {
		log.Error(err, "failed to update CaptureHub status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// ensureServer starts or reconfigures the gRPC server.
func (r *CaptureHubReconciler) ensureServer(ctx context.Context, hub *capturev1alpha1.CaptureHub) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	address := hub.Spec.GRPCAddress
	if address == "" {
		address = ":9443"
	}

	// If the server is already running on the right address, nothing to do.
	if r.server != nil && r.server.address == address {
		return nil
	}

	// Stop existing server if address changed.
	if r.server != nil {
		r.Log.Info("Stopping existing gRPC server for reconfiguration")
		r.cancel()
		r.server.Stop()
		r.server = nil
		r.cancel = nil
	}

	r.Log.Info("Starting gRPC server", "address", address)
	r.server = NewServer(address)

	serverCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel

	go func() {
		if err := r.server.Start(serverCtx); err != nil {
			r.Log.Error(err, "gRPC server stopped with error")
		}
	}()

	return nil
}

// stopServer gracefully stops the gRPC server.
func (r *CaptureHubReconciler) stopServer() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.server != nil {
		r.cancel()
		r.server.Stop()
		r.server = nil
		r.cancel = nil
	}
}

// updateStatus writes aggregated spoke data to the CaptureHub CR status.
func (r *CaptureHubReconciler) updateStatus(ctx context.Context, hub *capturev1alpha1.CaptureHub) error {
	r.mu.Lock()
	srv := r.server
	r.mu.Unlock()

	if srv == nil {
		return fmt.Errorf("gRPC server not running")
	}

	hub.Status.ConnectedSpokes = srv.ConnectedSpokeCount()
	hub.Status.ActiveCaptures = srv.ActiveCaptureCount()

	spokeSnapshots := srv.SpokeStatuses()
	hub.Status.Spokes = make([]capturev1alpha1.CaptureHubSpokeStatus, len(spokeSnapshots))
	for i, ss := range spokeSnapshots {
		t := metav1.NewTime(ss.LastHeartbeat)
		hub.Status.Spokes[i] = capturev1alpha1.CaptureHubSpokeStatus{
			Name:           ss.Name,
			LastHeartbeat:  &t,
			ActiveCaptures: ss.ActiveCaptures,
		}
	}

	return r.Status().Update(ctx, hub)
}

// GetServer returns the current gRPC server instance (for testing).
func (r *CaptureHubReconciler) GetServer() *Server {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.server
}

