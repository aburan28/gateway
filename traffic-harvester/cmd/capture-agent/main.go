package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/traffic-harvester/traffic-harvester/internal/agent"
	"github.com/traffic-harvester/traffic-harvester/internal/storage"
)

func main() {
	var (
		httpPort      = flag.Int("http-port", 8080, "HTTP sink listen port")
		grpcPort      = flag.Int("grpc-port", 9090, "gRPC sink listen port")
		healthPort    = flag.Int("health-port", 8081, "Health/metrics listen port")
		storageType   = flag.String("storage-type", "efs", "Storage backend type (s3, gcs, efs, ebs)")
		storageConfig = flag.String("storage-config", "{}", "Storage backend config as JSON")
		captureID     = flag.String("capture-id", "", "Capture ID for file naming")
		maxBodyBytes  = flag.Int64("max-body-bytes", 1<<20, "Max request body size in bytes")
		batchSize     = flag.Int("batch-size", 100, "Buffered writer batch size")
		flushInterval = flag.Duration("flush-interval", 5*time.Second, "Buffered writer flush interval")
	)
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *captureID == "" {
		log.Error("--capture-id is required")
		os.Exit(1)
	}

	// Parse storage config JSON into the correct type
	storageCfg, err := parseStorageConfig(*storageType, *storageConfig)
	if err != nil {
		log.Error("failed to parse storage config", "error", err)
		os.Exit(1)
	}

	factory, err := storage.NewWriterFactory(*storageType, storageCfg)
	if err != nil {
		log.Error("failed to create storage writer factory", "error", err)
		os.Exit(1)
	}

	writer, err := factory.NewWriter(context.Background(), *captureID)
	if err != nil {
		log.Error("failed to create storage writer", "error", err)
		os.Exit(1)
	}

	bufferedWriter := agent.NewBufferedWriter(agent.BufferedWriterConfig{
		Writer:        writer,
		BatchSize:     *batchSize,
		FlushInterval: *flushInterval,
		Logger:        log,
	})

	handler := agent.NewCaptureHandler(agent.CaptureHandlerConfig{
		Writer:       bufferedWriter,
		MaxBodyBytes: *maxBodyBytes,
		Logger:       log,
	})

	server := agent.NewAgentServer(agent.AgentServerConfig{
		HTTPPort:   *httpPort,
		GRPCPort:   *grpcPort,
		HealthPort: *healthPort,
		Handler:    handler,
		Logger:     log,
	})

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Info("starting capture agent",
		"captureID", *captureID,
		"httpPort", *httpPort,
		"grpcPort", *grpcPort,
		"healthPort", *healthPort,
		"storageType", *storageType,
	)

	if err := server.Start(ctx); err != nil {
		log.Error("server exited with error", "error", err)
	}

	log.Info("shutting down buffered writer")
	if err := bufferedWriter.Close(); err != nil {
		log.Error("buffered writer close error", "error", err)
	}

	log.Info("capture agent stopped")
}

func parseStorageConfig(storageType, rawJSON string) (any, error) {
	switch storageType {
	case "s3":
		var cfg storage.S3Config
		if err := json.Unmarshal([]byte(rawJSON), &cfg); err != nil {
			return nil, fmt.Errorf("parse s3 config: %w", err)
		}
		return cfg, nil
	case "gcs":
		var cfg storage.GCSConfig
		if err := json.Unmarshal([]byte(rawJSON), &cfg); err != nil {
			return nil, fmt.Errorf("parse gcs config: %w", err)
		}
		return cfg, nil
	case "efs":
		var cfg storage.EFSConfig
		if err := json.Unmarshal([]byte(rawJSON), &cfg); err != nil {
			return nil, fmt.Errorf("parse efs config: %w", err)
		}
		return cfg, nil
	case "ebs":
		var cfg storage.EBSConfig
		if err := json.Unmarshal([]byte(rawJSON), &cfg); err != nil {
			return nil, fmt.Errorf("parse ebs config: %w", err)
		}
		return cfg, nil
	default:
		return nil, fmt.Errorf("unsupported storage type %q", storageType)
	}
}