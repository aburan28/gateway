package spoke

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	capturev1alpha1 "github.com/traffic-harvester/traffic-harvester/api/v1alpha1"
)

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = capturev1alpha1.AddToScheme(s)
	_ = gwapiv1.Install(s)
	return s
}

func TestReconcile_CreatesResources(t *testing.T) {
	scheme := testScheme()
	tc := newTestTrafficCapture("capture-1", "default")
	storage := newTestStorage()
	route := &gwapiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: gwapiv1.HTTPRouteSpec{
			Rules: []gwapiv1.HTTPRouteRule{
				{
					BackendRefs: []gwapiv1.HTTPBackendRef{
						{BackendRef: gwapiv1.BackendRef{
							BackendObjectReference: gwapiv1.BackendObjectReference{
								Name: "backend-svc",
								Port: ptrTo(gwapiv1.PortNumber(8080)),
							},
						}},
					},
				},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(tc, storage, route).
		WithStatusSubresource(tc).
		Build()

	r := &TrafficCaptureReconciler{
		Client: cl,
		Scheme: scheme,
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "capture-1", Namespace: "default"}}
	_, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// Verify Deployment was created
	deploy := &appsv1.Deployment{}
	if err := cl.Get(context.Background(), types.NamespacedName{
		Name:      "capture-1-capture-agent",
		Namespace: "default",
	}, deploy); err != nil {
		t.Fatalf("expected Deployment to be created: %v", err)
	}

	// Verify Service was created
	svc := &corev1.Service{}
	if err := cl.Get(context.Background(), types.NamespacedName{
		Name:      "capture-1-capture-agent",
		Namespace: "default",
	}, svc); err != nil {
		t.Fatalf("expected Service to be created: %v", err)
	}

	// Verify HPA was created
	hpa := &autoscalingv2.HorizontalPodAutoscaler{}
	if err := cl.Get(context.Background(), types.NamespacedName{
		Name:      "capture-1-capture-agent",
		Namespace: "default",
	}, hpa); err != nil {
		t.Fatalf("expected HPA to be created: %v", err)
	}

	// Verify finalizer was added
	updatedTC := &capturev1alpha1.TrafficCapture{}
	if err := cl.Get(context.Background(), req.NamespacedName, updatedTC); err != nil {
		t.Fatalf("failed to get updated TrafficCapture: %v", err)
	}
	hasFinalizer := false
	for _, f := range updatedTC.Finalizers {
		if f == finalizerName {
			hasFinalizer = true
			break
		}
	}
	if !hasFinalizer {
		t.Error("expected finalizer to be present")
	}

	// Verify mirror filter was added to HTTPRoute
	updatedRoute := &gwapiv1.HTTPRoute{}
	if err := cl.Get(context.Background(), types.NamespacedName{
		Name:      "test-route",
		Namespace: "default",
	}, updatedRoute); err != nil {
		t.Fatalf("failed to get updated HTTPRoute: %v", err)
	}

	if len(updatedRoute.Spec.Rules) == 0 {
		t.Fatal("expected rules")
	}
	found := false
	for _, f := range updatedRoute.Spec.Rules[0].Filters {
		if f.Type == gwapiv1.HTTPRouteFilterRequestMirror {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected RequestMirror filter on HTTPRoute")
	}
}

func TestReconcile_NotFound(t *testing.T) {
	scheme := testScheme()
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	r := &TrafficCaptureReconciler{Client: cl, Scheme: scheme}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "nonexistent", Namespace: "default"}}
	_, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("expected no error for not-found, got: %v", err)
	}
}

