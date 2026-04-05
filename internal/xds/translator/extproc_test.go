// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package translator

import (
	"testing"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	"github.com/stretchr/testify/assert"

	"github.com/envoyproxy/gateway/internal/ir"
)

func TestTranslateExtProcBodyProcessingModeGRPC(t *testing.T) {
	mode := ir.ExtProcBodyGRPC

	got := translateExtProcBodyProcessingMode(&mode)

	assert.Equal(t, extprocv3.ProcessingMode_GRPC, got)
}

func TestBuildProcessingModeGRPC(t *testing.T) {
	requestMode := ir.ExtProcBodyGRPC
	responseMode := ir.ExtProcBodyGRPC
	extProc := &ir.ExtProc{
		RequestHeaderProcessing:    true,
		RequestBodyProcessingMode:  &requestMode,
		ResponseHeaderProcessing:   true,
		ResponseBodyProcessingMode: &responseMode,
	}

	got := buildProcessingMode(extProc)

	assert.Equal(t, extprocv3.ProcessingMode_SEND, got.RequestHeaderMode)
	assert.Equal(t, extprocv3.ProcessingMode_GRPC, got.RequestBodyMode)
	assert.Equal(t, extprocv3.ProcessingMode_SKIP, got.RequestTrailerMode)
	assert.Equal(t, extprocv3.ProcessingMode_SEND, got.ResponseHeaderMode)
	assert.Equal(t, extprocv3.ProcessingMode_GRPC, got.ResponseBodyMode)
	assert.Equal(t, extprocv3.ProcessingMode_SKIP, got.ResponseTrailerMode)
}
