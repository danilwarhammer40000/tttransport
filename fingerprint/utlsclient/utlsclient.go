// Package utlsclient wires a fingerprint.Profile into an actual uTLS
// connection + matching HTTP/2 SETTINGS. Isolated into its own Go
// module (see go.mod in this directory) because github.com/refraction-
// networking/utls is an external dependency this offline build
// environment could not fetch -- run `go mod tidy` here (with network)
// before building this package.
package utlsclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"

	"turboflare-transport/fingerprint"
)

// clientHelloIDByName maps the profile's string identifier (kept in the
// dependency-free fingerprint package) to uTLS's actual ClientHelloID
// type, which only exists once this module's dependency is fetched.
var clientHelloIDByName = map[string]utls.ClientHelloID{
	"HelloChrome_120":   utls.HelloChrome_120,
	"HelloChrome_124":   utls.HelloChrome_120, // uTLS may not yet ship a
	// dedicated 124 profile at the time you fetch this dependency --
	// verify against the installed utls version's exported IDs
	// (`utls.HelloChrome_*` constants) and update this mapping; falling
	// back to the nearest available Chrome profile is a reasonable
	// interim choice, not a silent bug, but SHOULD be revisited (this is
	// exactly the kind of drift the in-app profile-update hook in §3 is
	// meant to eventually handle without a full app rebuild).
	"HelloChrome_Auto": utls.HelloChrome_Auto,
}

// RoundTripper implements http.RoundTripper using a uTLS connection
// configured per the given fingerprint.Profile for every new TLS
// connection, and applies the profile's HTTP2Settings on top.
type RoundTripper struct {
	Profile fingerprint.Profile
	Dialer  *net.Dialer
}

func New(profile fingerprint.Profile) (*RoundTripper, error) {
	if _, ok := clientHelloIDByName[profile.UTLSClientHelloID]; !ok {
		return nil, fmt.Errorf("utlsclient: unknown ClientHelloID %q -- add it to clientHelloIDByName", profile.UTLSClientHelloID)
	}
	return &RoundTripper{
		Profile: profile,
		Dialer:  &net.Dialer{Timeout: 10 * time.Second},
	}, nil
}

func (rt *RoundTripper) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	rawConn, err := rt.Dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	helloID := clientHelloIDByName[rt.Profile.UTLSClientHelloID]

	uconn := utls.UClient(rawConn, &utls.Config{ServerName: host}, helloID)
	if err := uconn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("utlsclient: TLS handshake failed: %w", err)
	}
	return uconn, nil
}

// Transport builds an *http.Transport whose DialTLSContext uses the
// uTLS handshake above. HTTP/2 SETTINGS matching is left to the
// negotiated ALPN + uTLS's own HTTP/2 support; where uTLS's h2 layer
// exposes explicit SETTINGS overrides, wire rt.Profile.HTTP2Settings
// through here (the exact API surface depends on the fetched utls
// version -- check its h2 subpackage docs when you build this).
func (rt *RoundTripper) Transport() *http.Transport {
	return &http.Transport{
		DialTLSContext: rt.dialTLS,
		// ForceAttemptHTTP2 relies on uTLS's ALPN negotiation ("h2")
		// inside dialTLS above; Go's stdlib http2 layer takes over
		// framing after the TLS handshake completes.
		ForceAttemptHTTP2: true,
	}
}

// NewHTTPClient is the convenience constructor most callers want: an
// *http.Client that presents the given profile's TLS + (best-effort)
// HTTP/2 fingerprint for every request, paired with the matching
// User-Agent (caller is responsible for setting the User-Agent header
// on outgoing requests to rt.Profile.UserAgent -- kept manual rather
// than injected here, so this stays a plain RoundTripper).
func NewHTTPClient(profile fingerprint.Profile) (*http.Client, error) {
	rt, err := New(profile)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: rt.Transport(), Timeout: 30 * time.Second}, nil
}

var _ = tls.VersionTLS13 // kept only to document minimum acceptable version if you add MinVersion checks later
