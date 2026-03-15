package spoke

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	capturev1alpha1 "github.com/traffic-harvester/traffic-harvester/api/v1alpha1"
)

const (
	defaultCaptureAgentImage = "traffic-harvester/capture-agent:latest"
	defaultReplicas          int32 = 1
	defaultMinReplicas       int32 = 1
	defaultMaxReplicas       int32 = 10
	defaultTargetCPU         int32 = 70

	labelApp            = "app.kubernetes.io/name"
	labelInstance        = "app.kubernetes.io/instance"
	labelComponent       = "app.kubernetes.io/component"
	labelManagedBy       = "app.kubernetes.io/managed-by"
	componentCaptureAgent = "capture-agent"
	managedByValue       = "traffic-harvester"
)

// CaptureAgentImage can be overridden at build time.
var CaptureAgentImage = defaultCaptureAgentImage

// BuildDeployment builds a Deployment for capture agent pods.
func BuildDeployment(tc *capturev1alpha1.TrafficCapture, storage *capturev1alpha1.CaptureStorage) *appsv1.Deployment {
	replicas := defaultReplicas
	if tc.Spec.Agent != nil && tc.Spec.Agent.Replicas != nil {
		replicas = *tc.Spec.Agent.Replicas
	}

	labels := agentLabels(tc)

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      AgentDeploymentName(tc),
			Namespace: tc.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "capture-agent",
							Image: CaptureAgentImage,
							Ports: []corev1.ContainerPort{
								{Name: "http", ContainerPort: 8080, Protocol: corev1.ProtocolTCP},
								{Name: "grpc", ContainerPort: 9090, Protocol: corev1.ProtocolTCP},
							},
							Env:       buildEnvVars(tc, storage),
							Resources: defaultResources(),
						},
					},
				},
			},
		},
	}
}

// BuildService builds a ClusterIP Service for the capture agent.
func BuildService(tc *capturev1alpha1.TrafficCapture) *corev1.Service {
	labels := agentLabels(tc)
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      AgentServiceName(tc),
			Namespace: tc.Namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: labels,
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 8080, Protocol: corev1.ProtocolTCP},
				{Name: "grpc", Port: 9090, Protocol: corev1.ProtocolTCP},
			},
		},
	}
}

// BuildHPA builds a HorizontalPodAutoscaler for the capture agent Deployment.
func BuildHPA(tc *capturev1alpha1.TrafficCapture) *autoscalingv2.HorizontalPodAutoscaler {
	minReplicas := defaultMinReplicas
	maxReplicas := defaultMaxReplicas
	targetCPU := defaultTargetCPU

	if tc.Spec.Agent != nil {
		if tc.Spec.Agent.MinReplicas != nil {
			minReplicas = *tc.Spec.Agent.MinReplicas
		}
		if tc.Spec.Agent.MaxReplicas != nil {
			maxReplicas = *tc.Spec.Agent.MaxReplicas
		}
		if tc.Spec.Agent.TargetCPU != nil {
			targetCPU = *tc.Spec.Agent.TargetCPU
		}
	}

	return &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-capture-agent", tc.Name),
			Namespace: tc.Namespace,
			Labels:    agentLabels(tc),
		},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       AgentDeploymentName(tc),
			},
			MinReplicas: &minReplicas,
			MaxReplicas: maxReplicas,
			Metrics: []autoscalingv2.MetricSpec{
				{
					Type: autoscalingv2.ResourceMetricSourceType,
					Resource: &autoscalingv2.ResourceMetricSource{
						Name: corev1.ResourceCPU,
						Target: autoscalingv2.MetricTarget{
							Type:               autoscalingv2.UtilizationMetricType,
							AverageUtilization: &targetCPU,
						},
					},
				},
			},
		},
	}
}



func agentLabels(tc *capturev1alpha1.TrafficCapture) map[string]string {
	return map[string]string{
		labelApp:       componentCaptureAgent,
		labelInstance:   tc.Name,
		labelComponent: componentCaptureAgent,
		labelManagedBy: managedByValue,
	}
}

func buildEnvVars(tc *capturev1alpha1.TrafficCapture, storage *capturev1alpha1.CaptureStorage) []corev1.EnvVar {
	envs := []corev1.EnvVar{
		{Name: "CAPTURE_ID", Value: fmt.Sprintf("%s/%s", tc.Namespace, tc.Name)},
		{Name: "STORAGE_TYPE", Value: string(storage.Spec.Type)},
	}

	switch storage.Spec.Type {
	case capturev1alpha1.CaptureStorageTypeS3:
		if storage.Spec.S3 != nil {
			envs = append(envs,
				corev1.EnvVar{Name: "S3_BUCKET", Value: storage.Spec.S3.Bucket},
				corev1.EnvVar{Name: "S3_REGION", Value: storage.Spec.S3.Region},
			)
			if storage.Spec.S3.Prefix != nil {
				envs = append(envs, corev1.EnvVar{Name: "S3_PREFIX", Value: *storage.Spec.S3.Prefix})
			}
		}
	case capturev1alpha1.CaptureStorageTypeGCS:
		if storage.Spec.GCS != nil {
			envs = append(envs, corev1.EnvVar{Name: "GCS_BUCKET", Value: storage.Spec.GCS.Bucket})
			if storage.Spec.GCS.Prefix != nil {
				envs = append(envs, corev1.EnvVar{Name: "GCS_PREFIX", Value: *storage.Spec.GCS.Prefix})
			}
		}
	case capturev1alpha1.CaptureStorageTypeEFS:
		if storage.Spec.EFS != nil {
			envs = append(envs,
				corev1.EnvVar{Name: "EFS_FILESYSTEM_ID", Value: storage.Spec.EFS.FileSystemID},
				corev1.EnvVar{Name: "EFS_MOUNT_PATH", Value: storage.Spec.EFS.MountPath},
			)
		}
	case capturev1alpha1.CaptureStorageTypeEBS:
		if storage.Spec.EBS != nil {
			envs = append(envs,
				corev1.EnvVar{Name: "EBS_VOLUME_ID", Value: storage.Spec.EBS.VolumeID},
				corev1.EnvVar{Name: "EBS_MOUNT_PATH", Value: storage.Spec.EBS.MountPath},
			)
		}
	}

	// Capture settings
	if tc.Spec.Capture.IncludeHeaders != nil {
		envs = append(envs, corev1.EnvVar{Name: "CAPTURE_INCLUDE_HEADERS", Value: fmt.Sprintf("%v", *tc.Spec.Capture.IncludeHeaders)})
	}
	if tc.Spec.Capture.IncludeBody != nil {
		envs = append(envs, corev1.EnvVar{Name: "CAPTURE_INCLUDE_BODY", Value: fmt.Sprintf("%v", *tc.Spec.Capture.IncludeBody)})
	}
	if tc.Spec.Capture.MaxBodyBytes != nil {
		envs = append(envs, corev1.EnvVar{Name: "CAPTURE_MAX_BODY_BYTES", Value: fmt.Sprintf("%d", *tc.Spec.Capture.MaxBodyBytes)})
	}

	return envs
}

func defaultResources() corev1.ResourceRequirements {
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("500m"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	}
}