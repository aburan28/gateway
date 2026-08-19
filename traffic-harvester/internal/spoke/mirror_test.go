package spoke

import (
	"testing"

	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestBuildHTTPMirrorFilter(t *testing.T) {
	filter := buildHTTPMirrorFilter("default", "my-capture-agent")

	if filter.Type != gwapiv1.HTTPRouteFilterRequestMirror {
		t.Errorf("expected filter type RequestMirror, got %s", filter.Type)
	}
	if filter.RequestMirror == nil {
		t.Fatal("expected RequestMirror to be non-nil")
	}
	if string(filter.RequestMirror.BackendRef.Name) != "my-capture-agent" {
		t.Errorf("expected backend ref name my-capture-agent, got %s", filter.RequestMirror.BackendRef.Name)
	}
	if filter.RequestMirror.BackendRef.Port == nil || *filter.RequestMirror.BackendRef.Port != 8080 {
		t.Errorf("expected port 8080")
	}
	if filter.RequestMirror.BackendRef.Namespace == nil || string(*filter.RequestMirror.BackendRef.Namespace) != "default" {
		t.Error("expected namespace default")
	}
}

func TestBuildGRPCMirrorFilter(t *testing.T) {
	filter := buildGRPCMirrorFilter("production", "grpc-capture-agent")

	if filter.Type != gwapiv1.GRPCRouteFilterRequestMirror {
		t.Errorf("expected filter type RequestMirror, got %s", filter.Type)
	}
	if filter.RequestMirror == nil {
		t.Fatal("expected RequestMirror to be non-nil")
	}
	if string(filter.RequestMirror.BackendRef.Name) != "grpc-capture-agent" {
		t.Errorf("expected backend ref name grpc-capture-agent, got %s", filter.RequestMirror.BackendRef.Name)
	}
}

func TestHasHTTPMirrorFilter(t *testing.T) {
	filters := []gwapiv1.HTTPRouteFilter{
		buildHTTPMirrorFilter("default", "agent-svc"),
	}

	if !hasHTTPMirrorFilter(filters, "agent-svc") {
		t.Error("expected to find mirror filter for agent-svc")
	}
	if hasHTTPMirrorFilter(filters, "other-svc") {
		t.Error("should not find mirror filter for other-svc")
	}
	if hasHTTPMirrorFilter(nil, "agent-svc") {
		t.Error("should not find mirror filter in nil slice")
	}
}

func TestRemoveHTTPMirrorFilters(t *testing.T) {
	filters := []gwapiv1.HTTPRouteFilter{
		{Type: gwapiv1.HTTPRouteFilterRequestHeaderModifier},
		buildHTTPMirrorFilter("default", "agent-svc"),
		{Type: gwapiv1.HTTPRouteFilterURLRewrite},
	}

	result := removeHTTPMirrorFilters(filters, "agent-svc")
	if len(result) != 2 {
		t.Fatalf("expected 2 filters after removal, got %d", len(result))
	}
	for _, f := range result {
		if f.Type == gwapiv1.HTTPRouteFilterRequestMirror {
			t.Error("mirror filter should have been removed")
		}
	}
}

func TestRemoveHTTPMirrorFiltersKeepsOtherMirrors(t *testing.T) {
	filters := []gwapiv1.HTTPRouteFilter{
		buildHTTPMirrorFilter("default", "agent-svc-1"),
		buildHTTPMirrorFilter("default", "agent-svc-2"),
	}

	result := removeHTTPMirrorFilters(filters, "agent-svc-1")
	if len(result) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(result))
	}
	if string(result[0].RequestMirror.BackendRef.Name) != "agent-svc-2" {
		t.Errorf("expected agent-svc-2 to remain, got %s", result[0].RequestMirror.BackendRef.Name)
	}
}

func TestHasGRPCMirrorFilter(t *testing.T) {
	filters := []gwapiv1.GRPCRouteFilter{
		buildGRPCMirrorFilter("default", "grpc-agent"),
	}

	if !hasGRPCMirrorFilter(filters, "grpc-agent") {
		t.Error("expected to find mirror filter")
	}
	if hasGRPCMirrorFilter(filters, "other") {
		t.Error("should not find mirror filter for other")
	}
}

func TestRemoveGRPCMirrorFilters(t *testing.T) {
	filters := []gwapiv1.GRPCRouteFilter{
		buildGRPCMirrorFilter("default", "grpc-agent"),
	}

	result := removeGRPCMirrorFilters(filters, "grpc-agent")
	if len(result) != 0 {
		t.Fatalf("expected 0 filters, got %d", len(result))
	}
}

func TestAgentServiceName(t *testing.T) {
	tc := newTestTrafficCapture("my-capture", "default")
	if AgentServiceName(tc) != "my-capture-capture-agent" {
		t.Errorf("expected my-capture-capture-agent, got %s", AgentServiceName(tc))
	}
}

func TestAgentDeploymentName(t *testing.T) {
	tc := newTestTrafficCapture("my-capture", "default")
	if AgentDeploymentName(tc) != "my-capture-capture-agent" {
		t.Errorf("expected my-capture-capture-agent, got %s", AgentDeploymentName(tc))
	}
}

