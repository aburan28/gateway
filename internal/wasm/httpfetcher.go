// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wasm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/envoyproxy/gateway/internal/logging"
	"github.com/envoyproxy/gateway/internal/utils/safehttp"
)

// Default values for ExponentialBackOff.
const (
	defaultInitialInterval = 500 * time.Millisecond
	defaultMaxInterval     = 60 * time.Second
	maxWasmSize            = 1024 * 1024 * 256
)

var (
	// Referred to https://en.wikipedia.org/wiki/Tar_(computing)#UStar_format
	tarMagicNumber = []byte{0x75, 0x73, 0x74, 0x61, 0x72}
	// Referred to https://en.wikipedia.org/wiki/Gzip#File_format
	gzMagicNumber = []byte{0x1f, 0x8b}
)

// HTTPFetcher fetches remote wasm module with HTTP get.
type HTTPFetcher struct {
	client          *http.Client
	insecureClient  *http.Client
	initialBackoff  time.Duration
	requestMaxRetry int
	logger          logging.Logger
}

// allowLoopbackForTests is flipped to true by tests via the
// EnableLoopbackForTesting helper so the SSRF guard permits the localhost
// httptest servers they spin up. Production code must never call the helper.
var allowLoopbackForTests bool

// EnableLoopbackForTesting permits the wasm HTTP fetcher to dial loopback
// addresses (127.0.0.0/8, ::1). Intended ONLY for use by tests in this
// package and adjacent packages that exercise the fetcher against
// httptest.NewServer. The function name is intentionally awkward to
// discourage accidental production use.
func EnableLoopbackForTesting() {
	allowLoopbackForTests = true
}

// NewHTTPFetcher create a new HTTP remote wasm module fetcher.
// requestTimeout is a timeout for each HTTP/HTTPS request.
// requestMaxRetry is # of maximum retries of HTTP/HTTPS requests.
//
// The returned fetcher is SSRF-hardened: hostname resolution is checked
// against a denylist of loopback, unspecified, link-local (including cloud
// instance metadata at 169.254.169.254), multicast and broadcast addresses
// before any TCP connect. The validated IP is the address the dialer
// actually connects to, closing the DNS-rebinding window. Redirects are
// capped at safehttp.DefaultMaxRedirects and each redirect target is
// re-validated.
//
// RFC1918 / ULA / CGNAT private addresses are permitted because in-cluster
// Wasm registries commonly live on ClusterIPs in those ranges. Pair with a
// NetworkPolicy if stricter egress isolation is required.
func NewHTTPFetcher(requestTimeout time.Duration, requestMaxRetry int, logger logging.Logger) *HTTPFetcher {
	if requestTimeout == 0 {
		requestTimeout = 5 * time.Second
	}
	// insecure mode disables TLS server-cert verification but retains the
	// SSRF dial-time host check. MinVersion is pinned so an insecure flag
	// cannot also re-enable TLS 1.0.
	insecureTransport := http.DefaultTransport.(*http.Transport).Clone()
	insecureTransport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // only used when the operator explicitly enables the insecure registry list
		MinVersion:         tls.VersionTLS12,
	}
	return &HTTPFetcher{
		client: safehttp.NewClient(safehttp.Options{
			Timeout:       requestTimeout,
			AllowPrivate:  true,
			AllowLoopback: allowLoopbackForTests,
		}),
		insecureClient: safehttp.NewClient(safehttp.Options{
			Timeout:       requestTimeout,
			AllowPrivate:  true,
			AllowLoopback: allowLoopbackForTests,
			Transport:     insecureTransport,
		}),
		initialBackoff:  time.Millisecond * 500,
		requestMaxRetry: requestMaxRetry,
		logger:          logger,
	}
}

// Fetch downloads a wasm module with HTTP get.
func (f *HTTPFetcher) Fetch(ctx context.Context, url string, allowInsecure bool) ([]byte, error) {
	c := f.client
	if allowInsecure {
		c = f.insecureClient
	}
	attempts := 0
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = defaultInitialInterval
	b.MaxInterval = defaultMaxInterval
	b.InitialInterval = f.initialBackoff

	var lastError error
	for attempts < f.requestMaxRetry {
		attempts++
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			f.logger.Info("wasm module download request failed", "error", err)
			return nil, err
		}
		resp, err := c.Do(req)
		if err != nil {
			lastError = err
			f.logger.Info("wasm module download request failed", "error", err)
			if ctx.Err() != nil {
				// If there is context timeout, exit this loop.
				return nil, fmt.Errorf("wasm module download failed after %v attempts, last error: %w", attempts, lastError)
			}
			time.Sleep(b.NextBackOff())
			continue
		}
		if resp.StatusCode == http.StatusOK {
			// Limit wasm module to 256mb; in reality, it must be much smaller
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxWasmSize))
			if err != nil {
				return nil, err
			}
			err = resp.Body.Close()
			if err != nil {
				f.logger.Info("wasm server connection is not closed", "error", err)
			}
			return unboxIfPossible(body), err
		}
		lastError = fmt.Errorf("wasm module download request failed: status code %v", resp.StatusCode)
		if retryable(resp.StatusCode) {
			// Limit wasm module to 256mb; in reality it must be much smaller
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxWasmSize))
			if err != nil {
				return nil, err
			}
			f.logger.Info("wasm module download failed", "status code", resp.StatusCode, "body", string(body))
			err = resp.Body.Close()
			if err != nil {
				f.logger.Info("wasm server connection is not closed", "error", err)
			}
			time.Sleep(b.NextBackOff())
			continue
		}
		err = resp.Body.Close()
		if err != nil {
			f.logger.Info("wasm server connection is not closed", "error", err)
		}
		break
	}
	return nil, fmt.Errorf("wasm module download failed after %v attempts, last error: %w", attempts, lastError)
}

func retryable(code int) bool {
	return code >= 500 &&
		(code != http.StatusNotImplemented &&
			code != http.StatusHTTPVersionNotSupported &&
			code != http.StatusNetworkAuthenticationRequired)
}

func isPosixTar(b []byte) bool {
	return len(b) > 262 && bytes.Equal(b[257:262], tarMagicNumber)
}

// wasm plugin should be the only file in the tarball.
func getFirstFileFromTar(b []byte) []byte {
	buf := bytes.NewBuffer(b)

	// Limit wasm module to 256mb; in reality it must be much smaller
	tr := tar.NewReader(io.LimitReader(buf, maxWasmSize))

	h, err := tr.Next()
	if err != nil {
		return nil
	}

	// Reject obviously-hostile tar headers BEFORE allocating: h.Size is
	// attacker-controlled and a 1<<60 entry would panic the controller via
	// OOM at `make([]byte, h.Size)`. The LimitReader above only bounds the
	// number of bytes the tar reader will subsequently *read*; it does not
	// bound the up-front allocation.
	if h.Size < 0 || h.Size > maxWasmSize {
		return nil
	}

	ret := make([]byte, h.Size)
	_, err = io.ReadFull(tr, ret)
	if err != nil {
		return nil
	}
	return ret
}

func isGZ(b []byte) bool {
	return len(b) > 2 && bytes.Equal(b[:2], gzMagicNumber)
}

func getFileFromGZ(b []byte) []byte {
	buf := bytes.NewBuffer(b)

	zr, err := gzip.NewReader(buf)
	if err != nil {
		return nil
	}

	// Cap the decompressed stream. The compressed input is already bounded
	// to maxWasmSize, but a 256 MiB gzip can decompress to many TB; without
	// this LimitReader a malicious server can OOM-kill the controller pod.
	ret, err := io.ReadAll(io.LimitReader(zr, maxWasmSize))
	if err != nil {
		return nil
	}
	return ret
}

// Just do the best effort.
// If an error is encountered, just return the original bytes.
// Errors will be handled upper layers.
func unboxIfPossible(origin []byte) []byte {
	b := origin
	for {
		switch {
		case isValidWasmBinary(b):
			return b
		case isGZ(b):
			if b = getFileFromGZ(b); b == nil {
				return origin
			}
		case isPosixTar(b):
			if b = getFirstFileFromTar(b); b == nil {
				return origin
			}
		default:
			return origin
		}
	}
}
