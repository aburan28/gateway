// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package wasm

import (
	"os"
	"testing"
)

// TestMain opts the wasm test suite into safehttp's loopback exception so
// the httptest.NewServer hosts (which bind to 127.0.0.1) are reachable.
// Production code paths must never call EnableLoopbackForTesting.
func TestMain(m *testing.M) {
	EnableLoopbackForTesting()
	os.Exit(m.Run())
}
