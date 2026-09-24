// Package gomobilebridge exposes a gomobile-bind-compatible surface
// over client.Client. gomobile bind only supports a restricted set of
// types across the language boundary (string, []byte, int, bool, error,
// and simple exported structs/interfaces) -- this package exists purely
// to adapt the richer Go API in client/ to that restriction, for
// consumption from Kotlin (see android/app/).
//
// Build note: this package itself only needs the stdlib-only main
// module (proto/transport/client/server), so `gomobile bind` here does
// NOT require the uTLS/SQLite external dependencies to produce a
// working .aar -- fingerprint/observability upgrades can be wired in
// later by extending this bridge once those subpackages are built with
// network access.
//
// CRASH-SAFETY NOTE (found via real-device testing): a Go panic that
// crosses the gomobile Go<->Kotlin boundary is NOT caught by a Kotlin
// try/catch -- only a properly RETURNED Go error gets converted into a
// catchable Kotlin exception. An unrecovered panic here crashes the
// entire app process, same as an unrecovered panic in any other
// goroutine. Every exported method below therefore recovers from any
// panic and converts it into a returned error (or, for methods with no
// error in their signature, logs and swallows it) instead of letting it
// propagate across the boundary.
package gomobilebridge

import (
	"encoding/hex"
	"fmt"
	"log"
	"sync"

	"turboflare-transport/android/vpntun"
	"turboflare-transport/client"
	"turboflare-transport/proto"
)

// BuildVersion is bumped by hand on every meaningful code change handed
// over for rebuild -- displayed in the app UI (MainActivity) so it's
// immediately visible whether a fresh .aar actually made it into the
// running app, instead of guessing from behavior alone. This directly
// answers "did my fix actually get applied?" -- a real, recurring
// problem during iterative on-device debugging.
const BuildVersion = "v4"

// Version returns the current gomobilebridge build version string.
func Version() string {
	return BuildVersion
}

// SessionHandle wraps client.Client behind gomobile-safe method
// signatures (no multi-return beyond (T, error), no slice-of-slices).
type SessionHandle struct {
	mu      sync.Mutex
	c       *client.Client
	pending [][]byte
}

// OpenSession performs the initial handshake. serverStaticPubHex is the
// server's 32-byte X25519 public key, hex-encoded (baked into the app's
// provisioning config). deviceIDHex is an 8-byte value, hex-encoded --
// generate it ONCE on first app launch and persist it (see
// DeviceIDGenerate below), never regenerate per PROTOCOL.md §0.
func OpenSession(baseURL, serverStaticPubHex, deviceIDHex, token string) (handle *SessionHandle, err error) {
	defer recoverToError(&err, "OpenSession")

	pubRaw, hexErr := hex.DecodeString(serverStaticPubHex)
	if hexErr != nil || len(pubRaw) != proto.X25519KeySize {
		return nil, fmt.Errorf("gomobilebridge: invalid server static pubkey hex")
	}
	pub, loadErr := proto.LoadX25519PublicKey(pubRaw)
	if loadErr != nil {
		return nil, fmt.Errorf("gomobilebridge: load server static pubkey: %w", loadErr)
	}

	deviceIDRaw, devErr := hex.DecodeString(deviceIDHex)
	if devErr != nil || len(deviceIDRaw) != 8 {
		return nil, fmt.Errorf("gomobilebridge: invalid device_id hex")
	}
	var deviceID uint64
	for _, b := range deviceIDRaw {
		deviceID = (deviceID << 8) | uint64(b)
	}

	c := client.New(baseURL, pub, deviceID, token)
	if openErr := c.Open(); openErr != nil {
		return nil, openErr
	}
	return &SessionHandle{c: c}, nil
}

// Reconnect should be called by the Android app when it detects a
// network change (ConnectivityManager.NetworkCallback), per the fixed
// reconnect design.
func (h *SessionHandle) Reconnect() (err error) {
	defer recoverToError(&err, "SessionHandle.Reconnect")
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.c.Reconnect()
}

// Push sends one payload chunk.
func (h *SessionHandle) Push(payload []byte) (err error) {
	defer recoverToError(&err, "SessionHandle.Push")
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.c.Push(payload)
}

// PullOne polls the download channel and returns exactly one ready
// payload, or nil if none are available yet. Call in a loop from a
// background coroutine -- gomobile bind can't express []( []byte ), so
// this trades a few extra calls for a bind-compatible signature.
func (h *SessionHandle) PullOne() (payload []byte, err error) {
	defer recoverToError(&err, "SessionHandle.PullOne")
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.pending) == 0 {
		got, pullErr := h.c.Pull()
		if pullErr != nil {
			return nil, pullErr
		}
		h.pending = got
	}
	if len(h.pending) == 0 {
		return nil, nil
	}
	next := h.pending[0]
	h.pending = h.pending[1:]
	return next, nil
}

// ConnectionIDHex exposes the current session's connection_id for
// display/debugging in the Android UI. Returns "" on any internal
// error/panic rather than propagating it -- this is a display-only
// helper, not worth complicating every caller's error handling for.
func (h *SessionHandle) ConnectionIDHex() (out string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("gomobilebridge: recovered panic in ConnectionIDHex: %v", r)
			out = ""
		}
	}()
	h.mu.Lock()
	defer h.mu.Unlock()
	return fmt.Sprintf("%08x", h.c.Session.ConnectionID)
}

// VpnTunnelHandle is the gomobile-bind-compatible wrapper around
// vpntun.TunnelHandle -- see TurboflareVpnService.kt for the caller.
type VpnTunnelHandle struct {
	inner *vpntun.TunnelHandle
}

// Stop tears down the VPN tunnel (closes the netstack and, with it, the
// TUN file descriptor).
func (v *VpnTunnelHandle) Stop() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("gomobilebridge: recovered panic in VpnTunnelHandle.Stop: %v", r)
		}
	}()
	v.inner.Stop()
}

// StartVpnTunnel builds the userspace TCP/IP stack over fd (an already-
// detached TUN file descriptor, see ParcelFileDescriptor.detachFd() in
// Kotlin) and begins relaying intercepted TCP flows through the
// TurboFlare protocol. fd is passed as int64 because gomobile bind does
// not support the plain `int` type across the language boundary on all
// platforms.
func StartVpnTunnel(fd int64, baseURL, serverPubHex, deviceIDHex, token string) (handle *VpnTunnelHandle, err error) {
	defer recoverToError(&err, "StartVpnTunnel")

	inner, startErr := vpntun.Start(int(fd), vpntun.Config{
		BaseURL:      baseURL,
		ServerPubHex: serverPubHex,
		DeviceIDHex:  deviceIDHex,
		Token:        token,
	})
	if startErr != nil {
		return nil, startErr
	}
	return &VpnTunnelHandle{inner: inner}, nil
}

// DrainVpnLogs returns and clears every log line the tunnel has
// produced since the last call -- poll this periodically (e.g. every
// 1-2 seconds while a VPN session is active) to show live tunnel
// activity in the app UI instead of requiring adb logcat.
func DrainVpnLogs() (out string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("gomobilebridge: recovered panic in DrainVpnLogs: %v", r)
			out = ""
		}
	}()
	return vpntun.DrainLogs()
}

// recoverToError is deferred at the top of every exported method that
// returns an error. If the method panics, it converts the panic into an
// error assigned to *errOut instead of letting it cross the Go<->Kotlin
// boundary as an unrecoverable crash. label identifies which method
// panicked, for logcat-based debugging.
func recoverToError(errOut *error, label string) {
	if r := recover(); r != nil {
		log.Printf("gomobilebridge: recovered panic in %s: %v", label, r)
		*errOut = fmt.Errorf("gomobilebridge: internal error in %s: %v", label, r)
	}
}
