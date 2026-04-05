// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package v1alpha1

// ProtoMessageExtractionMode defines how Envoy extracts messages for streaming RPCs.
// +kubebuilder:validation:Enum=FirstAndLast
type ProtoMessageExtractionMode string

const (
	// ProtoMessageExtractionModeFirstAndLast extracts the first and last message
	// for streaming request/response bodies.
	ProtoMessageExtractionModeFirstAndLast ProtoMessageExtractionMode = "FirstAndLast"
)

// ProtoMessageExtractionDirective defines how an individual protobuf field is extracted.
// +kubebuilder:validation:Enum=Extract;ExtractRedact;ExtractRepeatedCardinality
type ProtoMessageExtractionDirective string

const (
	// ProtoMessageExtractionDirectiveExtract extracts the field value as-is.
	ProtoMessageExtractionDirectiveExtract ProtoMessageExtractionDirective = "Extract"

	// ProtoMessageExtractionDirectiveExtractRedact extracts the field shape but redacts message contents.
	ProtoMessageExtractionDirectiveExtractRedact ProtoMessageExtractionDirective = "ExtractRedact"

	// ProtoMessageExtractionDirectiveExtractRepeatedCardinality extracts the number of
	// elements in a repeated top-level response field.
	ProtoMessageExtractionDirectiveExtractRepeatedCardinality ProtoMessageExtractionDirective = "ExtractRepeatedCardinality"
)

// MethodExtraction defines the extraction directives for a single gRPC method.
//
// +kubebuilder:validation:XValidation:rule="(has(self.requestExtractionByField) && size(self.requestExtractionByField) > 0) || (has(self.responseExtractionByField) && size(self.responseExtractionByField) > 0)",message="at least one requestExtractionByField or responseExtractionByField entry must be specified"
type MethodExtraction struct {
	// RequestExtractionByField maps protobuf field paths in the request message
	// to extraction directives.
	//
	// +optional
	RequestExtractionByField map[string]ProtoMessageExtractionDirective `json:"requestExtractionByField,omitempty"`

	// ResponseExtractionByField maps protobuf field paths in the response message
	// to extraction directives.
	//
	// +optional
	ResponseExtractionByField map[string]ProtoMessageExtractionDirective `json:"responseExtractionByField,omitempty"`
}

// ProtoMessageExtraction defines Envoy's proto_message_extraction HTTP filter.
//
// +kubebuilder:validation:XValidation:rule="self.descriptorSetRef.kind == 'ConfigMap' || self.descriptorSetRef.kind == 'Secret'",message="descriptorSetRef kind must be ConfigMap or Secret"
// +kubebuilder:validation:XValidation:rule="size(self.descriptorSetRef.group) == 0",message="descriptorSetRef group must be the core API group"
// +kubebuilder:validation:XValidation:rule="size(self.extractionByMethod) > 0",message="at least one extractionByMethod entry must be specified"
type ProtoMessageExtraction struct {
	// DescriptorSetRef selects the compiled protobuf descriptor set used by Envoy.
	// Store the descriptor bytes in `binaryData` when referencing a ConfigMap, or
	// in `data` when referencing a Secret.
	DescriptorSetRef LocalObjectKeyReference `json:"descriptorSetRef"`

	// Mode controls how Envoy extracts messages for streaming RPCs.
	//
	// +optional
	Mode *ProtoMessageExtractionMode `json:"mode,omitempty"`

	// ExtractionByMethod maps fully qualified gRPC methods
	// (${package}.${Service}.${Method}) to extraction directives.
	ExtractionByMethod map[string]MethodExtraction `json:"extractionByMethod"`
}
