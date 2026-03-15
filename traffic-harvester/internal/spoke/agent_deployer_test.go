package spoke

import (
	"testing"

	capturev1alpha1 "github.com/traffic-harvester/traffic-harvester/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func newTestTrafficCapture(name, ns string) *capturev1alpha1.TrafficCapture {
	return &capturev1alpha1.TrafficCapture{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: capturev1alpha1.TrafficCaptureSpec{
			TargetRef: gwapiv1.LocalPolicyTargetReference{
				Group: "gateway.networking.k8s.io",
				Kind:  "HTTPRoute",
				Name:  "test-route",
			},
			StorageRef: capturev1alpha1.CaptureStorageReference{Name: "test-storage"},
			Capture:    capturev1alpha1.CaptureSettings{},
		},
	}
}

func newTestStorage() *capturev1alpha1.CaptureStorage {
	prefix := "test/"
	return &capturev1alpha1.CaptureStorage{
		ObjectMeta: metav1.ObjectMeta{Name: "test-storage", Namespace: "default"},
		Spec: capturev1alpha1.CaptureStorageSpec{
			Type: capturev1alpha1.CaptureStorageTypeS3,
			S3: &capturev1alpha1.S3Config{
				Bucket: "test-bucket",
				Region: "us-east-1",
				Prefix: &prefix,
				CredentialsSecretRef: gwapiv1.SecretObjectReference{
					Name: "test-secret",
				},
			},
		},
		Status: capturev1alpha1.CaptureStorageStatus{
			Phase: capturev1alpha1.CaptureStoragePhaseReady,
		},
	}
}

func TestBuildDeployment(t *testing.T) {
	tc := newTestTrafficCapture("capture-1", "default")
	storage := newTestStorage()

	deploy := BuildDeployment(tc, storage)

	if deploy.Name != "capture-1-capture-agent" {
		t.Errorf("expected deployment name capture-1-capture-agent, got %s", deploy.Name)
	}
	if deploy.Namespace != "default" {
		t.Errorf("expected namespace default, got %s", deploy.Namespace)
	}
	if *deploy.Spec.Replicas != 1 {
		t.Errorf("expected 1 replica, got %d", *deploy.Spec.Replicas)
	}
	if len(deploy.Spec.Template.Spec.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(deploy.Spec.Template.Spec.Containers))
	}

	container := deploy.Spec.Template.Spec.Containers[0]
	if container.Image != CaptureAgentImage {
		t.Errorf("expected image %s, got %s", CaptureAgentImage, container.Image)
	}
	if len(container.Ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(container.Ports))
	}
	if container.Ports[0].ContainerPort != 8080 {
		t.Errorf("expected port 8080, got %d", container.Ports[0].ContainerPort)
	}
	if container.Ports[1].ContainerPort != 9090 {
		t.Errorf("expected port 9090, got %d", container.Ports[1].ContainerPort)
	}

	// Check env vars
	envMap := make(map[string]string)
	for _, env := range container.Env {
		envMap[env.Name] = env.Value
	}
	if envMap["CAPTURE_ID"] != "default/capture-1" {
		t.Errorf("expected CAPTURE_ID default/capture-1, got %s", envMap["CAPTURE_ID"])
	}
	if envMap["STORAGE_TYPE"] != "S3" {
		t.Errorf("expected STORAGE_TYPE S3, got %s", envMap["STORAGE_TYPE"])
	}
	if envMap["S3_BUCKET"] != "test-bucket" {
		t.Errorf("expected S3_BUCKET test-bucket, got %s", envMap["S3_BUCKET"])
	}
}

func TestBuildDeploymentWithScaling(t *testing.T) {
	tc := newTestTrafficCapture("capture-1", "default")
	replicas := int32(5)
	tc.Spec.Agent = &capturev1alpha1.AgentScalingSpec{Replicas: &replicas}
	storage := newTestStorage()

	deploy := BuildDeployment(tc, storage)
	if *deploy.Spec.Replicas != 5 {
		t.Errorf("expected 5 replicas, got %d", *deploy.Spec.Replicas)
	}
}

func TestBuildService(t *testing.T) {
	tc := newTestTrafficCapture("capture-1", "default")

	svc := BuildService(tc)

	if svc.Name != "capture-1-capture-agent" {
		t.Errorf("expected service name capture-1-capture-agent, got %s", svc.Name)
	}
	if len(svc.Spec.Ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(svc.Spec.Ports))
	}
	if svc.Spec.Ports[0].Port != 8080 {
		t.Errorf("expected port 8080, got %d", svc.Spec.Ports[0].Port)
	}
	if svc.Spec.Ports[1].Port != 9090 {
		t.Errorf("expected port 9090, got %d", svc.Spec.Ports[1].Port)
	}
}

func TestBuildHPA(t *testing.T) {
	tc := newTestTrafficCapture("capture-1", "default")
	minReplicas := int32(3)
	maxReplicas := int32(15)
	targetCPU := int32(80)
	tc.Spec.Agent = &capturev1alpha1.AgentScalingSpec{
		MinReplicas: &minReplicas,
		MaxReplicas: &maxReplicas,
		TargetCPU:   &targetCPU,
	}

	hpa := BuildHPA(tc)

	if hpa.Name != "capture-1-capture-agent" {
		t.Errorf("expected HPA name capture-1-capture-agent, got %s", hpa.Name)
	}
	if *hpa.Spec.MinReplicas != 3 {
		t.Errorf("expected min replicas 3, got %d", *hpa.Spec.MinReplicas)
	}
	if hpa.Spec.MaxReplicas != 15 {
		t.Errorf("expected max replicas 15, got %d", hpa.Spec.MaxReplicas)
	}
}

