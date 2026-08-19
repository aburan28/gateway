package spoke

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	capturev1alpha1 "github.com/traffic-harvester/traffic-harvester/api/v1alpha1"
	hubv1 "github.com/traffic-harvester/traffic-harvester/proto/hub/v1"
)

const (
	finalizerName = "capture.gateway.io/cleanup"
)

// TrafficCaptureReconciler reconciles a TrafficCapture object.
type TrafficCaptureReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	HubClient *HubClient // optional: nil when running in standalone mode
}

// +kubebuilder:rbac:groups=capture.gateway.io,resources=trafficcaptures,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=capture.gateway.io,resources=trafficcaptures/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=capture.gateway.io,resources=trafficcaptures/finalizers,verbs=update
// +kubebuilder:rbac:groups=capture.gateway.io,resources=capturestorages,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=autoscaling,resources=horizontalpodautoscalers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=grpcroutes,verbs=get;list;watch;update;patch

func (r *TrafficCaptureReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	tc := &capturev1alpha1.TrafficCapture{}
	if err := r.Get(ctx, req.NamespacedName, tc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Handle deletion
	if !tc.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, tc)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(tc, finalizerName) {
		controllerutil.AddFinalizer(tc, finalizerName)
		if err := r.Update(ctx, tc); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Check duration expiration
	if tc.Spec.Capture.Duration != nil && tc.Status.StartTime != nil {
		duration, err := time.ParseDuration(*tc.Spec.Capture.Duration)
		if err == nil && time.Since(tc.Status.StartTime.Time) > duration {
			logger.Info("TrafficCapture duration expired, completing")
			return r.setPhase(ctx, tc, capturev1alpha1.TrafficCapturePhaseCompleted)
		}
	}

	// Step 1: Validate CaptureStorage exists and is Ready
	storage := &capturev1alpha1.CaptureStorage{}
	storageKey := types.NamespacedName{Namespace: tc.Namespace, Name: string(tc.Spec.StorageRef.Name)}
	if err := r.Get(ctx, storageKey, storage); err != nil {
		logger.Error(err, "CaptureStorage not found", "storage", storageKey)
		return r.setPhaseWithCondition(ctx, tc, capturev1alpha1.TrafficCapturePhaseFailed,
			"StorageNotFound", fmt.Sprintf("CaptureStorage %s not found: %v", storageKey, err))
	}
	if storage.Status.Phase != capturev1alpha1.CaptureStoragePhaseReady {
		logger.Info("CaptureStorage not ready, requeuing", "storage", storageKey)
		return r.setPhaseWithCondition(ctx, tc, capturev1alpha1.TrafficCapturePhasePending,
			"StorageNotReady", fmt.Sprintf("CaptureStorage %s is not Ready", storageKey))
	}

	// Step 2: Create/update capture agent Deployment
	deploy := BuildDeployment(tc, storage)
	if err := controllerutil.SetControllerReference(tc, deploy, r.Scheme); err != nil {
		return ctrl.Result{}, fmt.Errorf("set owner reference on Deployment: %w", err)
	}
	if err := r.createOrUpdate(ctx, deploy); err != nil {
		return ctrl.Result{}, fmt.Errorf("create/update Deployment: %w", err)
	}

	// Step 3: Create/update capture agent Service
	svc := BuildService(tc)
	if err := controllerutil.SetControllerReference(tc, svc, r.Scheme); err != nil {
		return ctrl.Result{}, fmt.Errorf("set owner reference on Service: %w", err)
	}
	if err := r.createOrUpdate(ctx, svc); err != nil {
		return ctrl.Result{}, fmt.Errorf("create/update Service: %w", err)
	}

	// Step 4: Create/update HPA
	hpa := BuildHPA(tc)
	if err := controllerutil.SetControllerReference(tc, hpa, r.Scheme); err != nil {
		return ctrl.Result{}, fmt.Errorf("set owner reference on HPA: %w", err)
	}
	if err := r.createOrUpdate(ctx, hpa); err != nil {
		return ctrl.Result{}, fmt.Errorf("create/update HPA: %w", err)
	}

	// Step 5: Add mirror filter to target route
	agentSvcName := AgentServiceName(tc)
	if err := AddMirrorFilter(ctx, r.Client, tc, agentSvcName); err != nil {
		return ctrl.Result{}, fmt.Errorf("add mirror filter: %w", err)
	}

	// Step 6: Update status
	result, err := r.updateStatus(ctx, tc)
	if err != nil {
		return result, err
	}

	// Step 7: Report status to hub (best-effort, don't fail reconcile)
	r.reportToHub(ctx, tc)

	return result, nil
}

func (r *TrafficCaptureReconciler) reconcileDelete(ctx context.Context, tc *capturev1alpha1.TrafficCapture) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Remove mirror filter from target route
	if err := RemoveMirrorFilter(ctx, r.Client, tc); err != nil {
		logger.Error(err, "failed to remove mirror filter during cleanup")
		// Continue with cleanup even if mirror filter removal fails
	}

	// Remove finalizer to allow deletion (owned resources are garbage collected)
	controllerutil.RemoveFinalizer(tc, finalizerName)
	if err := r.Update(ctx, tc); err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("TrafficCapture cleanup complete")
	return ctrl.Result{}, nil
}

func (r *TrafficCaptureReconciler) updateStatus(ctx context.Context, tc *capturev1alpha1.TrafficCapture) (ctrl.Result, error) {
	// Get the current Deployment to check agent status
	deploy := &appsv1.Deployment{}
	deployKey := types.NamespacedName{Namespace: tc.Namespace, Name: AgentDeploymentName(tc)}
	if err := r.Get(ctx, deployKey, deploy); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
		return ctrl.Result{}, err
	}

	// Update agent status
	tc.Status.AgentStatus = &capturev1alpha1.CaptureAgentStatus{
		ReadyReplicas:   deploy.Status.ReadyReplicas,
		DesiredReplicas: *deploy.Spec.Replicas,
	}

	// Set phase
	if deploy.Status.ReadyReplicas > 0 {
		tc.Status.Phase = capturev1alpha1.TrafficCapturePhaseActive
		if tc.Status.StartTime == nil {
			now := metav1.Now()
			tc.Status.StartTime = &now
		}
	} else {
		tc.Status.Phase = capturev1alpha1.TrafficCapturePhasePending
	}

	// Set Ready condition
	setCondition(&tc.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             conditionStatus(deploy.Status.ReadyReplicas > 0),
		Reason:             "AgentDeployment",
		Message:            fmt.Sprintf("%d/%d agents ready", deploy.Status.ReadyReplicas, *deploy.Spec.Replicas),
		LastTransitionTime: metav1.Now(),
	})

	if err := r.Status().Update(ctx, tc); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *TrafficCaptureReconciler) setPhase(ctx context.Context, tc *capturev1alpha1.TrafficCapture, phase capturev1alpha1.TrafficCapturePhase) (ctrl.Result, error) {
	tc.Status.Phase = phase
	if err := r.Status().Update(ctx, tc); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *TrafficCaptureReconciler) setPhaseWithCondition(ctx context.Context, tc *capturev1alpha1.TrafficCapture, phase capturev1alpha1.TrafficCapturePhase, reason, message string) (ctrl.Result, error) {
	tc.Status.Phase = phase
	setCondition(&tc.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionFalse,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
	if err := r.Status().Update(ctx, tc); err != nil {
		return ctrl.Result{}, err
	}
	if phase == capturev1alpha1.TrafficCapturePhasePending {
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
	return ctrl.Result{}, nil
}

func (r *TrafficCaptureReconciler) createOrUpdate(ctx context.Context, obj client.Object) error {
	existing := obj.DeepCopyObject().(client.Object)
	err := r.Get(ctx, client.ObjectKeyFromObject(obj), existing)
	if apierrors.IsNotFound(err) {
		return r.Create(ctx, obj)
	}
	if err != nil {
		return err
	}
	obj.SetResourceVersion(existing.GetResourceVersion())
	return r.Update(ctx, obj)
}

func conditionStatus(ok bool) metav1.ConditionStatus {
	if ok {
		return metav1.ConditionTrue
	}
	return metav1.ConditionFalse
}

func setCondition(conditions *[]metav1.Condition, condition metav1.Condition) {
	for i, c := range *conditions {
		if c.Type == condition.Type {
			(*conditions)[i] = condition
			return
		}
	}
	*conditions = append(*conditions, condition)
}

// reportToHub sends the current capture status to the hub (best-effort).
func (r *TrafficCaptureReconciler) reportToHub(ctx context.Context, tc *capturev1alpha1.TrafficCapture) {
	if r.HubClient == nil || !r.HubClient.IsConnected() {
		return
	}

	logger := log.FromContext(ctx)

	phase := hubv1.CapturePhase_CAPTURE_PHASE_UNSPECIFIED
	switch tc.Status.Phase {
	case capturev1alpha1.TrafficCapturePhasePending:
		phase = hubv1.CapturePhase_CAPTURE_PHASE_PENDING
	case capturev1alpha1.TrafficCapturePhaseActive:
		phase = hubv1.CapturePhase_CAPTURE_PHASE_ACTIVE
	case capturev1alpha1.TrafficCapturePhaseCompleted:
		phase = hubv1.CapturePhase_CAPTURE_PHASE_COMPLETED
	case capturev1alpha1.TrafficCapturePhaseFailed:
		phase = hubv1.CapturePhase_CAPTURE_PHASE_FAILED
	}

	var readyReplicas, desiredReplicas int32
	if tc.Status.AgentStatus != nil {
		readyReplicas = tc.Status.AgentStatus.ReadyReplicas
		desiredReplicas = tc.Status.AgentStatus.DesiredReplicas
	}

	statuses := []*hubv1.CaptureStatusSummary{{
		CaptureName:      tc.Name,
		CaptureNamespace: tc.Namespace,
		Phase:            phase,
		CapturedRequests: tc.Status.CapturedRequests,
		ReadyReplicas:    readyReplicas,
		DesiredReplicas:  desiredReplicas,
	}}

	if err := r.HubClient.ReportStatus(ctx, statuses); err != nil {
		logger.Error(err, "failed to report status to hub (best-effort)")
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *TrafficCaptureReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&capturev1alpha1.TrafficCapture{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&autoscalingv2.HorizontalPodAutoscaler{}).
		Complete(r)
}

