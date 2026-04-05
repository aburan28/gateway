// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package translator

import (
	"errors"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	pmecfgv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/proto_message_extraction/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/anypb"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/ir"
	"github.com/envoyproxy/gateway/internal/xds/types"
)

func init() {
	registerHTTPFilter(&protoMessageExtraction{})
}

type protoMessageExtraction struct{}

var _ httpFilter = &protoMessageExtraction{}

// patchHCM builds and appends the proto message extraction filters to the HTTP
// Connection Manager if applicable and they do not already exist.
func (*protoMessageExtraction) patchHCM(mgr *hcmv3.HttpConnectionManager, irListener *ir.HTTPListener) error {
	var errs error

	if mgr == nil {
		return errors.New("hcm is nil")
	}
	if irListener == nil {
		return errors.New("ir listener is nil")
	}

	for _, route := range irListener.Routes {
		if !routeContainsProtoMessageExtraction(route) {
			continue
		}

		for i := range route.EnvoyExtensions.ProtoMessageExtractions {
			pm := &route.EnvoyExtensions.ProtoMessageExtractions[i]
			if hcmContainsFilter(mgr, protoMessageExtractionFilterName(pm)) {
				continue
			}

			filter, err := buildHCMProtoMessageExtractionFilter(pm)
			if err != nil {
				errs = errors.Join(errs, err)
				continue
			}

			mgr.HttpFilters = append(mgr.HttpFilters, filter)
		}
	}

	return errs
}

func buildHCMProtoMessageExtractionFilter(pm *ir.ProtoMessageExtraction) (*hcmv3.HttpFilter, error) {
	config, err := protoMessageExtractionConfig(pm)
	if err != nil {
		return nil, err
	}

	configAny, err := anypb.New(config)
	if err != nil {
		return nil, err
	}

	return &hcmv3.HttpFilter{
		Name:     protoMessageExtractionFilterName(pm),
		Disabled: true,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{
			TypedConfig: configAny,
		},
	}, nil
}

func protoMessageExtractionFilterName(pm *ir.ProtoMessageExtraction) string {
	return perRouteFilterName(egv1a1.EnvoyFilterProtoMessageExtraction, pm.Name)
}

func protoMessageExtractionConfig(pm *ir.ProtoMessageExtraction) (*pmecfgv3.ProtoMessageExtractionConfig, error) {
	config := &pmecfgv3.ProtoMessageExtractionConfig{
		DescriptorSet: &pmecfgv3.ProtoMessageExtractionConfig_DataSource{
			DataSource: &corev3.DataSource{
				Specifier: &corev3.DataSource_InlineBytes{InlineBytes: pm.DescriptorSet},
			},
		},
		ExtractionByMethod: make(map[string]*pmecfgv3.MethodExtraction, len(pm.ExtractionByMethod)),
	}

	if pm.Mode != nil {
		config.Mode = translateProtoMessageExtractionMode(*pm.Mode)
	}

	for method, extraction := range pm.ExtractionByMethod {
		methodConfig := &pmecfgv3.MethodExtraction{}
		if len(extraction.RequestExtractionByField) > 0 {
			methodConfig.RequestExtractionByField = make(map[string]pmecfgv3.MethodExtraction_ExtractDirective, len(extraction.RequestExtractionByField))
			for fieldPath, directive := range extraction.RequestExtractionByField {
				methodConfig.RequestExtractionByField[fieldPath] = translateProtoMessageExtractionDirective(directive)
			}
		}
		if len(extraction.ResponseExtractionByField) > 0 {
			methodConfig.ResponseExtractionByField = make(map[string]pmecfgv3.MethodExtraction_ExtractDirective, len(extraction.ResponseExtractionByField))
			for fieldPath, directive := range extraction.ResponseExtractionByField {
				methodConfig.ResponseExtractionByField[fieldPath] = translateProtoMessageExtractionDirective(directive)
			}
		}
		config.ExtractionByMethod[method] = methodConfig
	}

	if err := config.ValidateAll(); err != nil {
		return nil, err
	}

	return config, nil
}

func translateProtoMessageExtractionMode(mode ir.ProtoMessageExtractionMode) pmecfgv3.ProtoMessageExtractionConfig_ExtractMode {
	switch mode {
	case ir.ProtoMessageExtractionModeFirstAndLast:
		return pmecfgv3.ProtoMessageExtractionConfig_FIRST_AND_LAST
	default:
		return pmecfgv3.ProtoMessageExtractionConfig_ExtractMode_UNSPECIFIED
	}
}

func translateProtoMessageExtractionDirective(directive ir.ProtoMessageExtractionDirective) pmecfgv3.MethodExtraction_ExtractDirective {
	switch directive {
	case ir.ProtoMessageExtractionDirectiveExtract:
		return pmecfgv3.MethodExtraction_EXTRACT
	case ir.ProtoMessageExtractionDirectiveExtractRedact:
		return pmecfgv3.MethodExtraction_EXTRACT_REDACT
	case ir.ProtoMessageExtractionDirectiveExtractRepeatedCardinality:
		return pmecfgv3.MethodExtraction_EXTRACT_REPEATED_CARDINALITY
	default:
		return pmecfgv3.MethodExtraction_ExtractDirective_UNSPECIFIED
	}
}

func routeContainsProtoMessageExtraction(irRoute *ir.HTTPRoute) bool {
	if irRoute == nil {
		return false
	}

	return irRoute.EnvoyExtensions != nil && len(irRoute.EnvoyExtensions.ProtoMessageExtractions) > 0
}

// patchResources is a no-op for proto message extraction because it embeds the
// descriptor set bytes directly in the filter config.
func (*protoMessageExtraction) patchResources(_ *types.ResourceVersionTable, _ []*ir.HTTPRoute) error {
	return nil
}

// patchRoute enables the corresponding proto message extraction filter for the provided route.
func (*protoMessageExtraction) patchRoute(route *routev3.Route, irRoute *ir.HTTPRoute, _ *ir.HTTPListener) error {
	if route == nil {
		return errors.New("xds route is nil")
	}
	if irRoute == nil {
		return errors.New("ir route is nil")
	}
	if irRoute.EnvoyExtensions == nil {
		return nil
	}

	for i := range irRoute.EnvoyExtensions.ProtoMessageExtractions {
		pm := &irRoute.EnvoyExtensions.ProtoMessageExtractions[i]
		filterName := protoMessageExtractionFilterName(pm)
		if err := enableFilterOnRoute(route, filterName, &routev3.FilterConfig{
			Config: &anypb.Any{},
		}); err != nil {
			return err
		}
	}

	return nil
}
