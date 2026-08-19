package integration

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	capturev1alpha1 "github.com/traffic-harvester/traffic-harvester/api/v1alpha1"
)

func TestCaptureStorageCanBeCreated(t *testing.T) {
	ns := createTestNamespace(t)

	storage := &capturev1alpha1.CaptureStorage{
		ObjectMeta: metav1.ObjectMeta{Name: "s3-storage", Namespace: ns},
		Spec: capturev1alpha1.CaptureStorageSpec{
			Type: capturev1alpha1.CaptureStorageTypeS3,
			S3: &capturev1alpha1.S3Config{
				Bucket: "test-bucket",
				Region: "us-east-1",
				CredentialsSecretRef: gwSecretRef("s3-creds"),
			},
		},
	}
	if err := k8sClient.Create(ctx, storage); err != nil {
		t.Fatalf("creating CaptureStorage: %v", err)
	}

	// Verify we can retrieve it
	got := &capturev1alpha1.CaptureStorage{}
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(storage), got); err != nil {
		t.Fatalf("getting CaptureStorage: %v", err)
	}
	if got.Spec.Type != capturev1alpha1.CaptureStorageTypeS3 {
		t.Fatalf("expected type S3, got %s", got.Spec.Type)
	}
}

func TestCaptureStorageStatusUpdate(t *testing.T) {
	ns := createTestNamespace(t)

	storage := newCaptureStorage(ns, "status-test")
	if err := k8sClient.Create(ctx, storage); err != nil {
		t.Fatalf("creating CaptureStorage: %v", err)
	}

	// Set status to Ready
	setStorageReady(t, storage)

	// Verify status persisted
	got := &capturev1alpha1.CaptureStorage{}
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(storage), got); err != nil {
		t.Fatalf("getting CaptureStorage: %v", err)
	}
	if got.Status.Phase != capturev1alpha1.CaptureStoragePhaseReady {
		t.Fatalf("expected phase Ready, got %s", got.Status.Phase)
	}
	if len(got.Status.Conditions) == 0 {
		t.Fatal("expected at least one condition")
	}
}

func TestCaptureStorageAllTypes(t *testing.T) {
	ns := createTestNamespace(t)

	tests := []struct {
		name string
		spec capturev1alpha1.CaptureStorageSpec
	}{
		{
			name: "gcs",
			spec: capturev1alpha1.CaptureStorageSpec{
				Type: capturev1alpha1.CaptureStorageTypeGCS,
				GCS: &capturev1alpha1.GCSConfig{
					Bucket:               "test-gcs-bucket",
					CredentialsSecretRef: gwSecretRef("gcs-creds"),
				},
			},
		},
		{
			name: "efs",
			spec: capturev1alpha1.CaptureStorageSpec{
				Type: capturev1alpha1.CaptureStorageTypeEFS,
				EFS: &capturev1alpha1.EFSConfig{
					FileSystemID: "fs-123",
					MountPath:    "/mnt/efs",
				},
			},
		},
		{
			name: "ebs",
			spec: capturev1alpha1.CaptureStorageSpec{
				Type: capturev1alpha1.CaptureStorageTypeEBS,
				EBS: &capturev1alpha1.EBSConfig{
					VolumeID:  "vol-123",
					MountPath: "/mnt/ebs",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := &capturev1alpha1.CaptureStorage{
				ObjectMeta: metav1.ObjectMeta{Name: tt.name + "-storage", Namespace: ns},
				Spec:       tt.spec,
			}
			if err := k8sClient.Create(ctx, storage); err != nil {
				t.Fatalf("creating %s CaptureStorage: %v", tt.name, err)
			}

			got := &capturev1alpha1.CaptureStorage{}
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(storage), got); err != nil {
				t.Fatalf("getting %s CaptureStorage: %v", tt.name, err)
			}
			if got.Spec.Type != tt.spec.Type {
				t.Fatalf("expected type %s, got %s", tt.spec.Type, got.Spec.Type)
			}
		})
	}
}

