package integration

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	capturev1alpha1 "github.com/traffic-harvester/traffic-harvester/api/v1alpha1"
)

func TestTrafficCaptureDeletionCleansUp(t *testing.T) {
	ns := createTestNamespace(t)

	// Setup: CaptureStorage + HTTPRoute + TrafficCapture
	storage := newCaptureStorage(ns, "del-storage")
	if err := k8sClient.Create(ctx, storage); err != nil {
		t.Fatalf("creating CaptureStorage: %v", err)
	}
	setStorageReady(t, storage)

	route := newHTTPRoute(ns, "del-route")
	if err := k8sClient.Create(ctx, route); err != nil {
		t.Fatalf("creating HTTPRoute: %v", err)
	}

	tc := newTrafficCapture(ns, "del-capture", "del-route", "del-storage")
	if err := k8sClient.Create(ctx, tc); err != nil {
		t.Fatalf("creating TrafficCapture: %v", err)
	}

	// Wait for resources to be created
	deployKey := types.NamespacedName{Namespace: ns, Name: "del-capture-capture-agent"}
	waitForObject(t, &appsv1.Deployment{}, deployKey, 15*time.Second)

	svcKey := types.NamespacedName{Namespace: ns, Name: "del-capture-capture-agent"}
	waitForObject(t, &corev1.Service{}, svcKey, 5*time.Second)

	// Verify mirror filter was added
	waitForCondition(t, 10*time.Second, func() bool {
		updated := &gwapiv1.HTTPRoute{}
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(route), updated); err != nil {
			return false
		}
		return hasMirrorFilter(updated)
	})

	// Now delete the TrafficCapture
	if err := k8sClient.Delete(ctx, tc); err != nil {
		t.Fatalf("deleting TrafficCapture: %v", err)
	}

	// Wait for TrafficCapture to be fully removed (finalizer should clean up)
	tcKey := types.NamespacedName{Namespace: ns, Name: "del-capture"}
	waitForAbsence(t, &capturev1alpha1.TrafficCapture{}, tcKey, 15*time.Second)

	// Verify mirror filter was removed from HTTPRoute
	waitForCondition(t, 10*time.Second, func() bool {
		updated := &gwapiv1.HTTPRoute{}
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(route), updated); err != nil {
			return false
		}
		return !hasMirrorFilter(updated)
	})

	// Verify owned resources are deleted (via garbage collection / owner refs)
	// Note: In envtest, GC may not run. We check the TrafficCapture is gone
	// and mirror filter is removed, which confirms the reconcileDelete ran.
}

func TestTrafficCaptureFailsWithoutStorage(t *testing.T) {
	ns := createTestNamespace(t)

	// Create HTTPRoute
	route := newHTTPRoute(ns, "nostorage-route")
	if err := k8sClient.Create(ctx, route); err != nil {
		t.Fatalf("creating HTTPRoute: %v", err)
	}

	// Create TrafficCapture referencing non-existent storage
	tc := newTrafficCapture(ns, "nostorage-capture", "nostorage-route", "does-not-exist")
	if err := k8sClient.Create(ctx, tc); err != nil {
		t.Fatalf("creating TrafficCapture: %v", err)
	}

	// Wait for the status to indicate failure
	waitForCondition(t, 15*time.Second, func() bool {
		got := &capturev1alpha1.TrafficCapture{}
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(tc), got); err != nil {
			return false
		}
		return got.Status.Phase == capturev1alpha1.TrafficCapturePhaseFailed
	})
}

func hasMirrorFilter(route *gwapiv1.HTTPRoute) bool {
	for _, rule := range route.Spec.Rules {
		for _, f := range rule.Filters {
			if f.Type == gwapiv1.HTTPRouteFilterRequestMirror {
				return true
			}
		}
	}
	return false
}

