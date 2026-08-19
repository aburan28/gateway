package main

import (
	"context"
	"flag"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	capturev1alpha1 "github.com/traffic-harvester/traffic-harvester/api/v1alpha1"
	"github.com/traffic-harvester/traffic-harvester/internal/spoke"
	hubv1 "github.com/traffic-harvester/traffic-harvester/proto/hub/v1"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(capturev1alpha1.AddToScheme(scheme))
	utilruntime.Must(gwapiv1.Install(scheme))
}

func main() {
	var (
		metricsAddr     string
		healthProbeAddr string
		hubAddress      string
		spokeName       string
		clusterID       string
		leaderElect     bool
	)

	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metrics endpoint binds to.")
	flag.StringVar(&healthProbeAddr, "health-probe-addr", ":8081", "The address the health probe endpoint binds to.")
	flag.StringVar(&hubAddress, "hub-address", "", "The gRPC address of the hub (optional, spoke works standalone if empty).")
	flag.StringVar(&spokeName, "spoke-name", "", "The name of this spoke cluster (defaults to hostname).")
	flag.StringVar(&clusterID, "cluster-id", "", "The cluster identifier for this spoke.")
	flag.BoolVar(&leaderElect, "leader-elect", false, "Enable leader election for controller manager.")
	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	setupLog := ctrl.Log.WithName("setup")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: healthProbeAddr,
		LeaderElection:         leaderElect,
		LeaderElectionID:       "spoke.capture.gateway.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Set up hub client (optional)
	var hubClient *spoke.HubClient
	if hubAddress != "" {
		if spokeName == "" {
			hostname, _ := os.Hostname()
			spokeName = hostname
		}
		if clusterID == "" {
			clusterID = spokeName
		}

		hubClient = spoke.NewHubClient(spoke.HubClientConfig{
			HubAddress: hubAddress,
			SpokeName:  spokeName,
			ClusterID:  clusterID,
			Logger:     setupLog,
		})

		hubClient.OnDirective = func(resp *hubv1.WatchDirectivesResponse) {
			d := resp.GetDirective()
			if d != nil {
				setupLog.Info("received directive from hub",
					"action", d.Action,
					"capture", d.CaptureName,
					"namespace", d.CaptureNamespace,
				)
			}
		}

		ctx := context.Background()
		if err := hubClient.Connect(ctx); err != nil {
			setupLog.Error(err, "failed to connect to hub, continuing in standalone mode")
			hubClient = nil
		} else {
			heartbeatSec, err := hubClient.Register(ctx)
			if err != nil {
				setupLog.Error(err, "failed to register with hub, continuing in standalone mode")
				hubClient.Close()
				hubClient = nil
			} else {
				interval := time.Duration(heartbeatSec) * time.Second
				if interval <= 0 {
					interval = 30 * time.Second
				}
				hubClient.StartHeartbeat(ctx, interval)
				hubClient.WatchDirectives(ctx)
				setupLog.Info("hub connection established", "heartbeatInterval", interval)
			}
		}
	} else {
		setupLog.Info("no hub address configured, running in standalone mode")
	}

	if err := (&spoke.TrafficCaptureReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		HubClient: hubClient,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "TrafficCapture")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting spoke controller manager",
		"hub-address", hubAddress,
		"spoke-name", spokeName,
	)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}

	// Graceful shutdown: deregister from hub
	if hubClient != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := hubClient.Deregister(shutdownCtx); err != nil {
			setupLog.Error(err, "failed to deregister from hub")
		}
		if err := hubClient.Close(); err != nil {
			setupLog.Error(err, "failed to close hub client")
		}
	}
}