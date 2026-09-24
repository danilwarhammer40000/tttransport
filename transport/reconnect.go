package transport

import (
	"sync"
	"time"
)

// ReconnectState implements the grace-period + redundant-packet design
// fixed for network handovers (wifi<->LTE): the grace period closes on
// WHICHEVER comes first -- an explicit server confirmation of the new
// session_key, or a timeout -- and the first outgoing data frames after
// a reconnect handshake are sent redundantly (duplicate sequence) until
// that confirmation arrives, so the server's existing dedup-by-sequence
// mechanism (transport/reorder.go) absorbs the duplicates for free.
type ReconnectState struct {
	mu sync.Mutex

	inGrace      bool
	graceStarted time.Time
	graceTimeout time.Duration

	keyConfirmed   bool
	redundantSent  int
	redundantTotal int
}

const (
	DefaultGraceTimeout   = 5 * time.Second
	DefaultRedundantCount = 3
)

func NewReconnectState() *ReconnectState {
	return &ReconnectState{
		graceTimeout:   DefaultGraceTimeout,
		redundantTotal: DefaultRedundantCount,
	}
}

// StartGrace begins a new grace period -- call this immediately after
// sending a reconnect handshake (i.e. a handshake frame carrying a
// non-zero connection_id for an existing session).
func (r *ReconnectState) StartGrace() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inGrace = true
	r.graceStarted = time.Now()
	r.keyConfirmed = false
	r.redundantSent = 0
}

// ConfirmKey is called when the peer's ACK carries FlagKeyConfirmed,
// closing the grace period early regardless of the timeout.
func (r *ReconnectState) ConfirmKey() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keyConfirmed = true
	r.inGrace = false
}

// Status reports the current grace-period state: whether it's active,
// and whether it has expired without confirmation (caller should treat
// an expired, unconfirmed grace period as a failed reconnect -- reset
// local state and start a brand-new session per the fixed design).
type GraceStatus struct {
	Active       bool
	Confirmed    bool
	Expired      bool // timed out without confirmation
	ElapsedSince time.Duration
}

func (r *ReconnectState) Status() GraceStatus {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.keyConfirmed {
		return GraceStatus{Active: false, Confirmed: true}
	}
	if !r.inGrace {
		return GraceStatus{}
	}
	elapsed := time.Since(r.graceStarted)
	if elapsed >= r.graceTimeout {
		return GraceStatus{Active: false, Confirmed: false, Expired: true, ElapsedSince: elapsed}
	}
	return GraceStatus{Active: true, Confirmed: false, Expired: false, ElapsedSince: elapsed}
}

// ShouldSendRedundant reports whether the NEXT outgoing frame should be
// sent as a redundant duplicate (i.e. we're still within the grace
// period, unconfirmed, and haven't exhausted the redundant-send budget).
func (r *ReconnectState) ShouldSendRedundant() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.keyConfirmed || !r.inGrace {
		return false
	}
	return r.redundantSent < r.redundantTotal
}

// MarkRedundantSent increments the redundant-send counter -- call once
// per actual duplicate transmission.
func (r *ReconnectState) MarkRedundantSent() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.redundantSent++
}

// Reset clears reconnect state, e.g. after a grace period expired and
// the caller is starting a brand-new session from scratch.
func (r *ReconnectState) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	*r = ReconnectState{graceTimeout: r.graceTimeout, redundantTotal: r.redundantTotal}
}
