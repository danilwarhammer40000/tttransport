// Package fingerprint holds the (dependency-free) profile DATA per
// PROTOCOL.md §3. The actual uTLS wiring that APPLIES a profile lives
// in fingerprint/utlsclient/ as a separate Go module, since the uTLS
// library is an external dependency this offline build environment
// cannot fetch -- see fingerprint/utlsclient/README.md.
package fingerprint

// Profile bundles a matched TLS ClientHello identity and HTTP/2 SETTINGS
// so the two never drift apart (the "combined library" decision -- see
// PROTOCOL.md §3: uTLS alone only covers TLS, so this struct forces
// every caller to set both together).
type Profile struct {
	ID string

	// UTLSClientHelloID is the string identifier used to select a
	// matching profile in the uTLS library (e.g. "HelloChrome_120",
	// "HelloChrome_Auto") -- kept as a string here (not the actual uTLS
	// type) so this package has zero external dependencies. The
	// utlsclient/ subpackage maps this string to the real uTLS type.
	UTLSClientHelloID string

	// UserAgent must match the Chrome version implied by
	// UTLSClientHelloID -- mismatched UA/TLS-version pairs are exactly
	// the kind of signal this whole layer exists to avoid.
	UserAgent string

	// HTTP2Settings mirrors real Chrome Mobile's SETTINGS frame values
	// for this version. Applied by utlsclient/ when establishing the
	// HTTP/2 connection.
	HTTP2Settings HTTP2Settings

	// Platform documents what this profile impersonates -- kept to
	// "Android only" per the fixed decision (no desktop/iOS profiles
	// mixed in, since a mobile device presenting a desktop fingerprint
	// is itself an anomaly).
	Platform string
}

type HTTP2Settings struct {
	HeaderTableSize      uint32
	EnablePush            uint32
	MaxConcurrentStreams  uint32
	InitialWindowSize     uint32
	MaxFrameSize          uint32
	MaxHeaderListSize     uint32
}

// Pool is the set of plausible Android/Chrome-Mobile profiles a device
// is randomized across EXACTLY ONCE, at token-activation time (see
// server/binding.go) -- never re-randomized afterward for the same
// device_id, per the fixed decision.
//
// NOTE: the exact SETTINGS values below are placeholders representative
// of recent Chrome Mobile releases at time of writing. Before relying on
// these, verify against a packet capture of real Chrome Mobile traffic
// (the observability test-mode probes in observability/testmode.go are
// built to check exactly this) and update per §3's "leave room for an
// in-app profile update" requirement.
var Pool = []Profile{
	{
		ID:                "android-chrome-120",
		UTLSClientHelloID: "HelloChrome_120",
		UserAgent:         "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		Platform:          "android",
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:     65536,
			EnablePush:          0,
			MaxConcurrentStreams: 1000,
			InitialWindowSize:   6291456,
			MaxFrameSize:        16384,
			MaxHeaderListSize:   262144,
		},
	},
	{
		ID:                "android-chrome-124",
		UTLSClientHelloID: "HelloChrome_124",
		UserAgent:         "Mozilla/5.0 (Linux; Android 14; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
		Platform:          "android",
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:     65536,
			EnablePush:          0,
			MaxConcurrentStreams: 1000,
			InitialWindowSize:   6291456,
			MaxFrameSize:        16384,
			MaxHeaderListSize:   262144,
		},
	},
	{
		ID:                "android-chrome-latest-auto",
		UTLSClientHelloID: "HelloChrome_Auto",
		UserAgent:         "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36",
		Platform:          "android",
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:     65536,
			EnablePush:          0,
			MaxConcurrentStreams: 1000,
			InitialWindowSize:   6291456,
			MaxFrameSize:        16384,
			MaxHeaderListSize:   262144,
		},
	},
}

// ByID looks up a profile by its stable ID (what gets persisted per
// device_id at activation time).
func ByID(id string) (Profile, bool) {
	for _, p := range Pool {
		if p.ID == id {
			return p, true
		}
	}
	return Profile{}, false
}
