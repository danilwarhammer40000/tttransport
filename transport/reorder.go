package transport

import "sync"

// ReorderBuffer reassembles the logical ordered stream from DataFrame
// payloads that may arrive in any order (per the CDN research: parallel
// HTTP transactions can complete out of order). Delivery to the
// application layer only happens once frames form a contiguous run
// starting at nextExpected -- exactly the "buffer 12, wait for 11" model
// described during design.
//
// Also provides idempotent duplicate handling (§29/§33 of the original
// research): re-delivering an already-consumed sequence number is a
// silent no-op, not an error -- this is what makes at-least-once HTTP
// delivery safe to turn into exactly-once logical processing.
type ReorderBuffer struct {
	mu           sync.Mutex
	nextExpected uint32
	pending      map[uint32][]byte
	started      bool
}

func NewReorderBuffer(startSequence uint32) *ReorderBuffer {
	return &ReorderBuffer{
		nextExpected: startSequence,
		pending:      make(map[uint32][]byte),
		started:      true,
	}
}

// Insert adds a received (sequence, payload) pair and returns any
// payloads that are now ready for in-order delivery, oldest first.
// Duplicate or already-delivered sequences are silently dropped.
func (r *ReorderBuffer) Insert(sequence uint32, payload []byte) [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.started {
		r.nextExpected = sequence
		r.started = true
	}

	// Already delivered (sequence is behind our watermark) -> duplicate,
	// drop per idempotency requirement.
	if sequence < r.nextExpected {
		return nil
	}

	if _, exists := r.pending[sequence]; exists {
		return nil // duplicate still-pending frame, drop
	}

	// Copy payload defensively -- caller's buffer may be reused.
	buf := make([]byte, len(payload))
	copy(buf, payload)
	r.pending[sequence] = buf

	var ready [][]byte
	for {
		p, ok := r.pending[r.nextExpected]
		if !ok {
			break
		}
		ready = append(ready, p)
		delete(r.pending, r.nextExpected)
		r.nextExpected++
	}
	return ready
}

// PendingCount reports how many out-of-order frames are currently held
// back waiting for a gap to fill -- useful as an observability metric
// (large/growing values suggest sustained packet loss on one path).
func (r *ReorderBuffer) PendingCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}

// NextExpected reports the next sequence number the buffer is waiting
// for -- this becomes the `ack` value sent back to the peer.
func (r *ReorderBuffer) NextExpected() uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.nextExpected
}
