package integration

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	capturev1alpha1 "github.com/traffic-harvester/traffic-harvester/api/v1alpha1"
)

func TestTrafficCaptureCreatesResources(t *testing.T) {
	ns := createTestNamespace(t)

	// Create prerequisite: CaptureStorage in Ready state
	storage := newCaptureStorage(ns, "test-storage")
	if err := k8sClient.Create(ctx, storage); err != nil {
		t.Fatalf("creating CaptureStorage: %v", err)
	}
	setStorageReady(t, storage)

	// Create prerequisite: HTTPRoute (target for mirror)
	route := newHTTPRoute(ns, "test-route")
	if err := k8sClient.Create(ctx, route); err != nil {
		t.Fatalf("creating HTTPRoute: %v", err)
	}

	// Create TrafficCapture
	tc := newTrafficCapture(ns, "test-capture", "test-route", "test-storage")
	if err := k8sClient.Create(ctx, tc); err != nil {
		t.Fatalf("creating TrafficCapture: %v", err)
	}

	// Wait for agent Deployment to be created
	deployKey := types.NamespacedName{Namespace: ns, Name: "test-capture-capture-agent"}
	waitForObject(t, &appsv1.Deployment{}, deployKey, 15*time.Second)

	// Verify Service was created
	svcKey := types.NamespacedName{Namespace: ns, Name: "test-capture-capture-agent"}
	waitForObject(t, &corev1.Service{}, svcKey, 5*time.Second)

	// Verify HPA was created
	hpaKey := types.NamespacedName{Namespace: ns, Name: "test-capture-capture-agent"}
	waitForObject(t, &autoscalingv2.HorizontalPodAutoscaler{}, hpaKey, 5*time.Second)

	// Verify mirror filter was added to HTTPRoute
	waitForCondition(t, 10*time.Second, func() bool {
		updated := &gwapiv1.HTTPRoute{}
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(route), updated); err != nil {
			return false
		}
		for _, rule := range updated.Spec.Rules {
			for _, f := range rule.Filters {
				if f.Type == gwapiv1.HTTPRouteFilterRequestMirror {
					return true
				}
			}
		}
		return false
	})
}

// --- helpers ---

func createTestNamespace(t *testing.T) string {
	t.Helper()
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-",
		},
	}
	if err := k8sClient.Create(ctx, ns); err != nil {
		t.Fatalf("creating namespace: %v", err)
	}
	t.Cleanup(func() {
		_ = k8sClient.Delete(ctx, ns)
	})
	return ns.Name
}

func newCaptureStorage(ns, name string) *capturev1alpha1.CaptureStorage {
	return &capturev1alpha1.CaptureStorage{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: capturev1alpha1.CaptureStorageSpec{
			Type: capturev1alpha1.CaptureStorageTypeEFS,
			EFS: &capturev1alpha1.EFSConfig{
				FileSystemID: "fs-test",
				MountPath:    "/mnt/capture",
			},
		},
	}
}

func setStorageReady(t *testing.T, storage *capturev1alpha1.CaptureStorage) {
	t.Helper()
	storage.Status.Phase = capturev1alpha1.CaptureStoragePhaseReady
	storage.Status.Conditions = []metav1.Condition{{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "ConfigValid",
		Message:            "Storage configuration is valid",
		LastTransitionTime: metav1.Now(),
	}}
	if err := k8sClient.Status().Update(ctx, storage); err != nil {
		t.Fatalf("setting storage status: %v", err)
	}
}

func newHTTPRoute(ns, name string) *gwapiv1.HTTPRoute {
	return &gwapiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: gwapiv1.HTTPRouteSpec{
			Rules: []gwapiv1.HTTPRouteRule{
				{
					BackendRefs: []gwapiv1.HTTPBackendRef{
						{
							BackendRef: gwapiv1.BackendRef{
								BackendObjectReference: gwapiv1.BackendObjectReference{
									Name: "backend-svc",
									Port: ptrTo(gwapiv1.PortNumber(80)),
								},
							},
						},
					},
				},
			},
		},
	}
}

func newTrafficCapture(ns, name, routeName, storageName string) *capturev1alpha1.TrafficCapture {
	return &capturev1alpha1.TrafficCapture{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: capturev1alpha1.TrafficCaptureSpec{
			TargetRef: gwapiv1.LocalPolicyTargetReference{
				Group: "gateway.networking.k8s.io",
				Kind:  "HTTPRoute",
				Name:  gwapiv1.ObjectName(routeName),
			},
			StorageRef: capturev1alpha1.CaptureStorageReference{
				Name: gwapiv1.ObjectName(storageName),
			},
			Capture: capturev1alpha1.CaptureSettings{},
		},
	}
}

func ptrTo[T any](v T) *T { return &v }

