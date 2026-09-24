package server

import (
	"sync"
	"time"
)

// Binding records which device_id currently "owns" a provisioning token.
type Binding struct {
	DeviceID uint64
	BoundAt  time.Time
	LastSeen time.Time
}

// TokenStore implements the account/token-based device binding fixed in
// PROTOCOL.md §0: one active device per token, atomic compare-and-set on
// first bind, explicit or inactivity-based revoke to let a user move to
// a new device without reissuing the provisioning link.
type TokenStore struct {
	mu       sync.Mutex
	bindings map[string]*Binding

	// InactivityTTL: a binding older than this (by LastSeen) is treated
	// as auto-revoked -- the next handshake attempt from ANY device_id
	// for that token succeeds and rebinds.
	InactivityTTL time.Duration
}

const DefaultInactivityTTL = 30 * 24 * time.Hour // 30 days, tune as needed

func NewTokenStore() *TokenStore {
	return &TokenStore{
		bindings:      make(map[string]*Binding),
		InactivityTTL: DefaultInactivityTTL,
	}
}

// BindResult is the outcome of an attempted bind.
type BindResult int

const (
	BindAccepted BindResult = iota // token now bound (freshly, or re-confirmed) to this device_id
	BindRejected                   // token is actively bound to a DIFFERENT device_id
	BindUnknownToken                // token was never issued (caller should reject the handshake entirely)
)

// KnownTokens would normally be validated against an issuance store
// (e.g. what the Telegram bot wrote when generating a provisioning
// link). For this prototype, tokens are pre-registered via RegisterToken.
type issuedToken struct{}

var _ = issuedToken{}

func (s *TokenStore) RegisterToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.bindings[token]; !exists {
		s.bindings[token] = nil // known, but not yet bound to a device
	}
}

// TryBind attempts to bind deviceID to token. Atomic: only one device_id
// can hold an active binding for a token at a time.
func (s *TokenStore) TryBind(token string, deviceID uint64) BindResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, known := s.bindings[token]
	if !known {
		return BindUnknownToken
	}

	now := time.Now()

	if existing == nil {
		s.bindings[token] = &Binding{DeviceID: deviceID, BoundAt: now, LastSeen: now}
		return BindAccepted
	}

	if existing.DeviceID == deviceID {
		existing.LastSeen = now
		return BindAccepted
	}

	// Different device holds the binding -- check inactivity auto-revoke.
	if now.Sub(existing.LastSeen) > s.InactivityTTL {
		s.bindings[token] = &Binding{DeviceID: deviceID, BoundAt: now, LastSeen: now}
		return BindAccepted
	}

	return BindRejected
}

// Touch updates LastSeen for an active binding -- call on every
// successful transaction, not just handshake, so InactivityTTL reflects
// real usage.
func (s *TokenStore) Touch(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.bindings[token]; ok && b != nil {
		b.LastSeen = time.Now()
	}
}

// Revoke manually clears a token's binding (e.g. user-issued /revoke
// command), freeing it for a new device on the next handshake.
func (s *TokenStore) Revoke(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, known := s.bindings[token]; known {
		s.bindings[token] = nil
	}
}
