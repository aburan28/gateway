// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package translator

import (
	"testing"

	pmecfgv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/proto_message_extraction/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/ir"
)

func TestProtoMessageExtractionConfig(t *testing.T) {
	pm := &ir.ProtoMessageExtraction{
		Name:          "proto-message-extraction",
		DescriptorSet: []byte("descriptor-bytes"),
		Mode:          ptrToProtoMessageExtractionMode(ir.ProtoMessageExtractionModeFirstAndLast),
		ExtractionByMethod: map[string]ir.MethodExtraction{
			"bookstore.Bookstore.GetShelf": {
				RequestExtractionByField: map[string]ir.ProtoMessageExtractionDirective{
					"shelf": ir.ProtoMessageExtractionDirectiveExtract,
				},
				ResponseExtractionByField: map[string]ir.ProtoMessageExtractionDirective{
					"books": ir.ProtoMessageExtractionDirectiveExtractRepeatedCardinality,
				},
			},
		},
	}

	config, err := protoMessageExtractionConfig(pm)
	require.NoError(t, err)
	require.NotNil(t, config)

	assert.Equal(t, pmecfgv3.ProtoMessageExtractionConfig_FIRST_AND_LAST, config.Mode)
	assert.Equal(t, []byte("descriptor-bytes"), config.GetDataSource().GetInlineBytes())
	require.Contains(t, config.ExtractionByMethod, "bookstore.Bookstore.GetShelf")
	assert.Equal(t, pmecfgv3.MethodExtraction_EXTRACT, config.ExtractionByMethod["bookstore.Bookstore.GetShelf"].RequestExtractionByField["shelf"])
	assert.Equal(t, pmecfgv3.MethodExtraction_EXTRACT_REPEATED_CARDINALITY, config.ExtractionByMethod["bookstore.Bookstore.GetShelf"].ResponseExtractionByField["books"])
}

func TestSortHTTPFiltersProtoMessageExtractionBeforeExtProc(t *testing.T) {
	filters := []*hcmv3.HttpFilter{
		httpFilterForTest(egv1a1.EnvoyFilterExtProc + "/envoyextensionpolicy/default/policy-for-http-route/0"),
		httpFilterForTest(egv1a1.EnvoyFilterProtoMessageExtraction + "/envoyextensionpolicy/default/policy-for-http-route/0"),
	}

	got := sortHTTPFilters(filters, nil)

	require.Len(t, got, 2)
	assert.Equal(t, string(egv1a1.EnvoyFilterProtoMessageExtraction)+"/envoyextensionpolicy/default/policy-for-http-route/0", got[0].Name)
	assert.Equal(t, string(egv1a1.EnvoyFilterExtProc)+"/envoyextensionpolicy/default/policy-for-http-route/0", got[1].Name)
}

func ptrToProtoMessageExtractionMode(mode ir.ProtoMessageExtractionMode) *ir.ProtoMessageExtractionMode {
	return &mode
}
