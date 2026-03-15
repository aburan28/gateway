package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	capturev1alpha1 "github.com/traffic-harvester/traffic-harvester/api/v1alpha1"
	"github.com/traffic-harvester/traffic-harvester/internal/spoke"
)

var (
	testEnv   *envtest.Environment
	cfg       *rest.Config
	k8sClient client.Client
	scheme    *runtime.Scheme
	ctx       context.Context
	cancel    context.CancelFunc
)

func TestMain(m *testing.M) {
	scheme = runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = capturev1alpha1.AddToScheme(scheme)
	_ = gwapiv1.Install(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = autoscalingv2.AddToScheme(scheme)

	// Find project root — CRDs are at config/crd/bases/
	crdDir := filepath.Join("..", "..", "config", "crd", "bases")

	// Locate Gateway API CRDs from the module cache
	gwAPICRDDir := gatewayAPICRDPath()

	crdPaths := []string{crdDir}
	if gwAPICRDDir != "" {
		crdPaths = append(crdPaths, gwAPICRDDir)
	}

	testEnv = &envtest.Environment{
		CRDDirectoryPaths: crdPaths,
		Scheme:            scheme,
	}

	var err error
	cfg, err = testEnv.Start()
	if err != nil {
		panic("failed to start envtest: " + err.Error())
	}

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		panic("failed to create client: " + err.Error())
	}

	// Start controller manager with the spoke reconciler
	ctx, cancel = context.WithCancel(context.Background())
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme,
	})
	if err != nil {
		panic("failed to create manager: " + err.Error())
	}

	reconciler := &spoke.TrafficCaptureReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		panic("failed to setup controller: " + err.Error())
	}

	go func() {
		if err := mgr.Start(ctx); err != nil {
			panic("failed to start manager: " + err.Error())
		}
	}()

	code := m.Run()

	cancel()
	_ = testEnv.Stop()
	os.Exit(code)
}


// gatewayAPICRDPath discovers the Gateway API CRD YAML directory from the Go module cache.
func gatewayAPICRDPath() string {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "sigs.k8s.io/gateway-api")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	dir := strings.TrimSpace(string(out))
	crdDir := filepath.Join(dir, "config", "crd", "standard")
	if _, err := os.Stat(crdDir); err == nil {
		return crdDir
	}
	return ""
}
