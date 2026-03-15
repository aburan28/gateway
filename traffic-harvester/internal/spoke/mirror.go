package spoke

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	capturev1alpha1 "github.com/traffic-harvester/traffic-harvester/api/v1alpha1"
)

const mirrorFilterAnnotationKey = "capture.gateway.io/traffic-capture"

// AddMirrorFilter adds a RequestMirror filter to the target HTTPRoute or GRPCRoute
// pointing to the capture agent Service. It is idempotent.
func AddMirrorFilter(ctx context.Context, cl client.Client, tc *capturev1alpha1.TrafficCapture, agentServiceName string) error {
	kind := string(tc.Spec.TargetRef.Kind)
	switch kind {
	case "HTTPRoute":
		return addHTTPRouteMirror(ctx, cl, tc, agentServiceName)
	case "GRPCRoute":
		return addGRPCRouteMirror(ctx, cl, tc, agentServiceName)
	default:
		return fmt.Errorf("unsupported target kind: %s", kind)
	}
}

// RemoveMirrorFilter removes the RequestMirror filter from the target HTTPRoute or GRPCRoute.
func RemoveMirrorFilter(ctx context.Context, cl client.Client, tc *capturev1alpha1.TrafficCapture) error {
	kind := string(tc.Spec.TargetRef.Kind)
	switch kind {
	case "HTTPRoute":
		return removeHTTPRouteMirror(ctx, cl, tc)
	case "GRPCRoute":
		return removeGRPCRouteMirror(ctx, cl, tc)
	default:
		return fmt.Errorf("unsupported target kind: %s", kind)
	}
}

func addHTTPRouteMirror(ctx context.Context, cl client.Client, tc *capturev1alpha1.TrafficCapture, agentServiceName string) error {
	route := &gwapiv1.HTTPRoute{}
	if err := cl.Get(ctx, client.ObjectKey{Namespace: tc.Namespace, Name: string(tc.Spec.TargetRef.Name)}, route); err != nil {
		return fmt.Errorf("get HTTPRoute %s: %w", tc.Spec.TargetRef.Name, err)
	}

	for i := range route.Spec.Rules {
		if hasHTTPMirrorFilter(route.Spec.Rules[i].Filters, agentServiceName) {
			continue
		}
		filter := buildHTTPMirrorFilter(tc.Namespace, agentServiceName)
		route.Spec.Rules[i].Filters = append(route.Spec.Rules[i].Filters, filter)
	}

	setAnnotation(route, mirrorFilterName(tc))
	return cl.Update(ctx, route)
}

func removeHTTPRouteMirror(ctx context.Context, cl client.Client, tc *capturev1alpha1.TrafficCapture) error {
	route := &gwapiv1.HTTPRoute{}
	if err := cl.Get(ctx, client.ObjectKey{Namespace: tc.Namespace, Name: string(tc.Spec.TargetRef.Name)}, route); err != nil {
		return client.IgnoreNotFound(err)
	}

	for i := range route.Spec.Rules {
		route.Spec.Rules[i].Filters = removeHTTPMirrorFilters(route.Spec.Rules[i].Filters, AgentServiceName(tc))
	}

	delete(route.Annotations, mirrorFilterAnnotationKey)
	return cl.Update(ctx, route)
}

func addGRPCRouteMirror(ctx context.Context, cl client.Client, tc *capturev1alpha1.TrafficCapture, agentServiceName string) error {
	route := &gwapiv1.GRPCRoute{}
	if err := cl.Get(ctx, client.ObjectKey{Namespace: tc.Namespace, Name: string(tc.Spec.TargetRef.Name)}, route); err != nil {
		return fmt.Errorf("get GRPCRoute %s: %w", tc.Spec.TargetRef.Name, err)
	}

	for i := range route.Spec.Rules {
		if hasGRPCMirrorFilter(route.Spec.Rules[i].Filters, agentServiceName) {
			continue
		}
		filter := buildGRPCMirrorFilter(tc.Namespace, agentServiceName)
		route.Spec.Rules[i].Filters = append(route.Spec.Rules[i].Filters, filter)
	}

	setAnnotation(route, mirrorFilterName(tc))
	return cl.Update(ctx, route)
}

func removeGRPCRouteMirror(ctx context.Context, cl client.Client, tc *capturev1alpha1.TrafficCapture) error {
	route := &gwapiv1.GRPCRoute{}
	if err := cl.Get(ctx, client.ObjectKey{Namespace: tc.Namespace, Name: string(tc.Spec.TargetRef.Name)}, route); err != nil {
		return client.IgnoreNotFound(err)
	}

	for i := range route.Spec.Rules {
		route.Spec.Rules[i].Filters = removeGRPCMirrorFilters(route.Spec.Rules[i].Filters, AgentServiceName(tc))
	}

	delete(route.Annotations, mirrorFilterAnnotationKey)
	return cl.Update(ctx, route)
}

func mirrorFilterName(tc *capturev1alpha1.TrafficCapture) string {
	return fmt.Sprintf("%s/%s", tc.Namespace, tc.Name)
}

// AgentServiceName returns the name of the capture agent Service for a TrafficCapture.
func AgentServiceName(tc *capturev1alpha1.TrafficCapture) string {
	return fmt.Sprintf("%s-capture-agent", tc.Name)
}

// AgentDeploymentName returns the name of the capture agent Deployment for a TrafficCapture.
func AgentDeploymentName(tc *capturev1alpha1.TrafficCapture) string {
	return fmt.Sprintf("%s-capture-agent", tc.Name)
}

func setAnnotation(obj client.Object, value string) {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations[mirrorFilterAnnotationKey] = value
	obj.SetAnnotations(annotations)
}

const (
	captureAgentHTTPPort gwapiv1.PortNumber = 8080
	captureAgentGRPCPort gwapiv1.PortNumber = 9090
)

func buildHTTPMirrorFilter(namespace, serviceName string) gwapiv1.HTTPRouteFilter {
	ns := gwapiv1.Namespace(namespace)
	return gwapiv1.HTTPRouteFilter{
		Type: gwapiv1.HTTPRouteFilterRequestMirror,
		RequestMirror: &gwapiv1.HTTPRequestMirrorFilter{
			BackendRef: gwapiv1.BackendObjectReference{
				Name:      gwapiv1.ObjectName(serviceName),
				Namespace: &ns,
				Port:      ptrTo(captureAgentHTTPPort),
			},
		},
	}
}

func buildGRPCMirrorFilter(namespace, serviceName string) gwapiv1.GRPCRouteFilter {
	ns := gwapiv1.Namespace(namespace)
	return gwapiv1.GRPCRouteFilter{
		Type: gwapiv1.GRPCRouteFilterRequestMirror,
		RequestMirror: &gwapiv1.HTTPRequestMirrorFilter{
			BackendRef: gwapiv1.BackendObjectReference{
				Name:      gwapiv1.ObjectName(serviceName),
				Namespace: &ns,
				Port:      ptrTo(captureAgentHTTPPort),
			},
		},
	}
}

func hasHTTPMirrorFilter(filters []gwapiv1.HTTPRouteFilter, filterName string) bool {
	for _, f := range filters {
		if f.Type == gwapiv1.HTTPRouteFilterRequestMirror && f.RequestMirror != nil {
			if string(f.RequestMirror.BackendRef.Name) == filterName {
				return true
			}
		}
	}
	return false
}

func hasGRPCMirrorFilter(filters []gwapiv1.GRPCRouteFilter, filterName string) bool {
	for _, f := range filters {
		if f.Type == gwapiv1.GRPCRouteFilterRequestMirror && f.RequestMirror != nil {
			if string(f.RequestMirror.BackendRef.Name) == filterName {
				return true
			}
		}
	}
	return false
}

func removeHTTPMirrorFilters(filters []gwapiv1.HTTPRouteFilter, agentServiceName string) []gwapiv1.HTTPRouteFilter {
	result := make([]gwapiv1.HTTPRouteFilter, 0, len(filters))
	for _, f := range filters {
		if f.Type == gwapiv1.HTTPRouteFilterRequestMirror && f.RequestMirror != nil {
			if string(f.RequestMirror.BackendRef.Name) == agentServiceName {
				continue
			}
		}
		result = append(result, f)
	}
	return result
}

func removeGRPCMirrorFilters(filters []gwapiv1.GRPCRouteFilter, agentServiceName string) []gwapiv1.GRPCRouteFilter {
	result := make([]gwapiv1.GRPCRouteFilter, 0, len(filters))
	for _, f := range filters {
		if f.Type == gwapiv1.GRPCRouteFilterRequestMirror && f.RequestMirror != nil {
			if string(f.RequestMirror.BackendRef.Name) == agentServiceName {
				continue
			}
		}
		result = append(result, f)
	}
	return result
}

func ptrTo[T any](v T) *T {
	return &v
}

