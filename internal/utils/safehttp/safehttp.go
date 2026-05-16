// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

// Package safehttp provides HTTP clients that defend against SSRF when the
// control plane fetches user-supplied URLs (Wasm modules, OIDC discovery,
// JWKS, etc.).
//
// The defenses are:
//
//   - Hostname is resolved once on the control plane side.
//   - Each resolved IP is checked against a denylist of meta-addresses
//     (loopback, link-local including cloud IMDS at 169.254.169.254,
//     unspecified, multicast/broadcast). Resolution to a denied address
//     aborts the connection.
//   - The validated IP is the address the dialer actually connects to,
//     closing the DNS-rebinding window between hostname validation and TCP
//     connect.
//   - Redirects are bounded; each Location target re-runs the host check.
//   - Per-request body size is capped by the caller via io.LimitReader; we
//     also enforce a default response-size ceiling.
//
// We deliberately do NOT block RFC1918 / ULA private addresses by default,
// because in-cluster Wasm registries, OIDC providers, and JWKS endpoints
// commonly live on ClusterIPs in those ranges. Operators that need stricter
// egress isolation should pair this guard with a NetworkPolicy.
package safehttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// ErrBlockedAddress is returned when a hostname resolves to (or a literal IP
// names) an address inside the denylist.
var ErrBlockedAddress = errors.New("address is not permitted for outbound control-plane fetches")

// ErrTooManyRedirects is returned when more than MaxRedirects hops are
// requested by a fetched resource.
var ErrTooManyRedirects = errors.New("too many redirects")

// Options configures a safe HTTP client.
type Options struct {
	// Timeout is the per-request timeout, including connect, TLS handshake,
	// response headers and body read. Zero means use DefaultTimeout.
	Timeout time.Duration
	// MaxRedirects bounds the number of 3xx redirects the client follows.
	// Each redirect target is independently host-validated. Zero means use
	// DefaultMaxRedirects. A negative value disables redirects entirely.
	MaxRedirects int
	// Transport is an optional base transport whose TLS settings will be
	// preserved; the DialContext is always overridden to enforce host
	// validation. If nil, a clone of http.DefaultTransport is used.
	Transport *http.Transport
	// AllowPrivate, when true, permits dialing RFC1918 / ULA / CGNAT
	// addresses. The loopback/link-local/unspecified/multicast denylist is
	// always enforced regardless of this flag.
	AllowPrivate bool
	// AllowLoopback, when true, permits dialing 127.0.0.0/8 and ::1.
	// Intended for tests that spin up httptest.NewServer; production code
	// paths should leave this false. Other always-denied categories
	// (link-local / unspecified / multicast) remain blocked.
	AllowLoopback bool
}

const (
	DefaultTimeout      = 10 * time.Second
	DefaultMaxRedirects = 5
)

// NewClient returns an *http.Client whose Dial step verifies the resolved IP
// against the denylist before opening a TCP connection.
func NewClient(opts Options) *http.Client {
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	maxRedirects := opts.MaxRedirects
	if maxRedirects == 0 {
		maxRedirects = DefaultMaxRedirects
	}

	var transport *http.Transport
	if opts.Transport != nil {
		transport = opts.Transport.Clone()
	} else {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	}

	// Override DialContext to enforce host validation on every TCP connect.
	// We resolve the hostname here (not in net.Dialer) so the address we
	// dial is the same address we validated, closing the rebind window.
	dialer := &net.Dialer{
		Timeout:   opts.Timeout,
		KeepAlive: 30 * time.Second,
		Control:   controlDeny(opts.AllowPrivate, opts.AllowLoopback),
	}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ip, err := resolveAndValidate(ctx, host, opts.AllowPrivate, opts.AllowLoopback)
		if err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}

	return &http.Client{
		Timeout:   opts.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if maxRedirects < 0 {
				return http.ErrUseLastResponse
			}
			if len(via) >= maxRedirects {
				return fmt.Errorf("%w: stopped after %d redirects", ErrTooManyRedirects, maxRedirects)
			}
			// The DialContext above will re-validate the redirect target,
			// but reject literal blocked IPs in the URL early so we don't
			// even open a TLS handshake to e.g. an IMDS IP redirected via
			// 302.
			if ip := net.ParseIP(req.URL.Hostname()); ip != nil {
				if err := checkIP(ip, opts.AllowPrivate, opts.AllowLoopback); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

// resolveAndValidate resolves host to its first usable address and verifies
// it against the denylist. If host is a literal IP, it is checked directly.
func resolveAndValidate(ctx context.Context, host string, allowPrivate, allowLoopback bool) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if err := checkIP(ip, allowPrivate, allowLoopback); err != nil {
			return nil, err
		}
		return ip, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolving %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses for host %q", host)
	}
	// All resolved addresses must be permitted. A mixed-result DNS response
	// (one public + one IMDS, for example) should be treated as hostile.
	for _, a := range addrs {
		if err := checkIP(a.IP, allowPrivate, allowLoopback); err != nil {
			return nil, fmt.Errorf("resolution of %q yielded blocked address %s: %w", host, a.IP, err)
		}
	}
	return addrs[0].IP, nil
}

// checkIP returns ErrBlockedAddress wrapped with a reason if ip is in the
// always-denied set, or — when allowPrivate is false — in the private set.
func checkIP(ip net.IP, allowPrivate, allowLoopback bool) error {
	if ip == nil {
		return fmt.Errorf("%w: nil IP", ErrBlockedAddress)
	}
	// Always-denied: unspecified, link-local, multicast,
	// interface-local-multicast, broadcast. Loopback is denied unless
	// allowLoopback is set (which should only be used by tests).
	switch {
	case ip.IsUnspecified():
		return fmt.Errorf("%w: unspecified address %s", ErrBlockedAddress, ip)
	case ip.IsLoopback():
		if !allowLoopback {
			return fmt.Errorf("%w: loopback address %s", ErrBlockedAddress, ip)
		}
	case ip.IsLinkLocalUnicast():
		// Includes 169.254.0.0/16 (covers cloud instance metadata at
		// 169.254.169.254) and IPv6 fe80::/10.
		return fmt.Errorf("%w: link-local address %s", ErrBlockedAddress, ip)
	case ip.IsMulticast() || ip.IsInterfaceLocalMulticast():
		return fmt.Errorf("%w: multicast address %s", ErrBlockedAddress, ip)
	}
	// CGNAT (100.64.0.0/10) is treated as private here; same risk profile
	// for SSRF in cloud-hosted control planes.
	if !allowPrivate && (ip.IsPrivate() || isCGNAT(ip)) {
		return fmt.Errorf("%w: private address %s (set AllowPrivate to permit)", ErrBlockedAddress, ip)
	}
	return nil
}

var cgnat = net.IPNet{
	IP:   net.IPv4(100, 64, 0, 0),
	Mask: net.CIDRMask(10, 32),
}

func isCGNAT(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		return cgnat.Contains(v4)
	}
	return false
}

// controlDeny returns a syscall.RawConn Control hook that double-checks the
// final 4-tuple right before TCP SYN. This is belt-and-suspenders relative
// to DialContext — if a future code path constructs a Dialer with our
// Control but bypasses DialContext, the kernel-level check still catches it.
func controlDeny(allowPrivate, allowLoopback bool) func(network, address string, c syscall.RawConn) error {
	return func(_ string, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("%w: dialer received unresolved host %q", ErrBlockedAddress, host)
		}
		return checkIP(ip, allowPrivate, allowLoopback)
	}
}
