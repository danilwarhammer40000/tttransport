package transport

import "sync"

// ReplayWindow implements a standard sliding-window anti-replay check
// over the explicit per-frame nonce_counter values introduced in
// proto.DataFrame's wire format fix (see proto/frame.go CHANGELOG note).
//
// This is deliberately separate from sequence-based reassembly
// (reorder.go): a nonce_counter can arrive "out of order" relative to
// other counters perfectly legitimately (parallel HTTP transactions
// completing in any order, per the CDN's documented behavior) -- that's
// fine and expected. What must NEVER happen is decrypting the exact same
// counter twice for the same session_key, which would indicate either a
// genuine retransmit-replay attack or a bug. The window tolerates
// legitimate reordering within WindowSize while still catching replays.
type ReplayWindow struct {
	mu        sync.Mutex
	size      uint32
	highest   uint32
	seen      uint64 // bitmap, bit i = (highest - i) was seen, for i in [0, size)
	initiated bool
}

const DefaultReplayWindowSize = 64

func NewReplayWindow() *ReplayWindow {
	return &ReplayWindow{size: DefaultReplayWindowSize}
}

// CheckAndMark returns true if counter is acceptable (not a replay) and
// marks it seen. Returns false if counter was already seen or falls
// below the trailing edge of the window (too old to distinguish from
// a replay reliably).
func (w *ReplayWindow) CheckAndMark(counter uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.initiated {
		w.initiated = true
		w.highest = counter
		w.seen = 1 // bit 0 set: highest itself seen
		return true
	}

	switch {
	case counter > w.highest:
		shift := counter - w.highest
		if shift >= 64 {
			w.seen = 0
		} else {
			w.seen <<= shift
		}
		w.seen |= 1
		w.highest = counter
		return true

	case counter == w.highest:
		return false // exact replay of the most recent counter

	default:
		diff := w.highest - counter
		if diff >= w.size || diff >= 64 {
			return false // too old, treat as replay/expired
		}
		bit := uint64(1) << diff
		if w.seen&bit != 0 {
			return false // already seen
		}
		w.seen |= bit
		return true
	}
}

// Reset clears the window -- called when a session's session_key
// rotates (new handshake / reconnect), since nonce_counter starts over
// at 0 for the new key and old high-water marks are no longer relevant.
func (w *ReplayWindow) Reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.initiated = false
	w.highest = 0
	w.seen = 0
}
