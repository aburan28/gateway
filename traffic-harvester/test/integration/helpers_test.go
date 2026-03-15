package integration

import (
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// waitForObject polls until the object exists in the API server or the timeout is reached.
func waitForObject(t *testing.T, obj client.Object, key types.NamespacedName, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		err := k8sClient.Get(ctx, key, obj)
		if err == nil {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %T %s", obj, key)
}

// waitForCondition polls until cond returns true or the timeout is reached.
func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("timed out waiting for condition")
}

// waitForAbsence polls until the object no longer exists.
func waitForAbsence(t *testing.T, obj client.Object, key types.NamespacedName, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		err := k8sClient.Get(ctx, key, obj)
		if err != nil {
			return // object is gone
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %T %s to be deleted", obj, key)
}



// gwSecretRef creates a SecretObjectReference for test fixtures.
func gwSecretRef(name string) gwapiv1.SecretObjectReference {
	return gwapiv1.SecretObjectReference{
		Name: gwapiv1.ObjectName(name),
	}
}