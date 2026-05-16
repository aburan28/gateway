// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package gatewayapi

import (
	"os"
	"testing"
)

// TestMain opts the gatewayapi test suite into the OIDC discovery loopback
// exception so unit tests that spin up httptest.NewServer (which binds to
// 127.0.0.1) can drive the discovery flow. Production code must never call
// EnableOIDCLoopbackForTesting.
func TestMain(m *testing.M) {
	EnableOIDCLoopbackForTesting()
	os.Exit(m.Run())
}
