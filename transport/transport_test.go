package transport

import (
	"testing"
	"time"

	"turboflare-transport/proto"
)

func TestReplayWindow_AcceptsInOrderAndOutOfOrder(t *testing.T) {
	w := NewReplayWindow()

	if !w.CheckAndMark(100) {
		t.Fatal("first counter should be accepted")
	}
	// Out-of-order but within window: legitimate under CDN reordering.
	if !w.CheckAndMark(105) {
		t.Fatal("higher counter should be accepted (advances window)")
	}
	if !w.CheckAndMark(102) {
		t.Fatal("counter within window behind highest should be accepted once")
	}
	// Exact replay of an already-seen counter must be rejected.
	if w.CheckAndMark(102) {
		t.Fatal("replay of already-seen counter must be rejected")
	}
	if w.CheckAndMark(105) {
		t.Fatal("replay of highest counter must be rejected")
	}
}

func TestReplayWindow_TooOldRejected(t *testing.T) {
	w := NewReplayWindow()
	w.CheckAndMark(1000)
	if w.CheckAndMark(1000 - DefaultReplayWindowSize - 1) {
		t.Fatal("counter far behind the window must be rejected")
	}
}

func TestReplayWindow_ResetOnRekey(t *testing.T) {
	w := NewReplayWindow()
	w.CheckAndMark(50)
	w.Reset()
	if !w.CheckAndMark(0) {
		t.Fatal("counter 0 must be acceptable again after Reset (new session_key)")
	}
}

func TestReorderBuffer_DeliversInOrder(t *testing.T) {
	rb := NewReorderBuffer(0)

	if ready := rb.Insert(1, []byte("b")); len(ready) != 0 {
		t.Fatalf("seq 1 arriving before seq 0 must be buffered, got %v", ready)
	}
	if ready := rb.Insert(2, []byte("c")); len(ready) != 0 {
		t.Fatalf("seq 2 must still be buffered")
	}
	ready := rb.Insert(0, []byte("a"))
	if len(ready) != 3 {
		t.Fatalf("filling the gap at seq 0 should flush seq 0,1,2 in order, got %d items", len(ready))
	}
	if string(ready[0]) != "a" || string(ready[1]) != "b" || string(ready[2]) != "c" {
		t.Fatalf("delivered out of order: %v", ready)
	}
}

func TestReorderBuffer_DuplicateIsIdempotent(t *testing.T) {
	rb := NewReorderBuffer(0)
	rb.Insert(0, []byte("a"))
	// Re-inserting an already-delivered sequence must be a silent no-op.
	ready := rb.Insert(0, []byte("a-duplicate"))
	if len(ready) != 0 {
		t.Fatalf("duplicate of already-delivered sequence must not be redelivered, got %v", ready)
	}
}

func TestCongestionController_BurstJumpsAndReturnsToBaseline(t *testing.T) {
	c := NewCongestionController()
	if c.CurrentWindow() != DefaultWBaseline {
		t.Fatalf("expected baseline window %d at start, got %d", DefaultWBaseline, c.CurrentWindow())
	}

	c.OnQueueNonEmpty()
	if w := c.CurrentWindow(); w != DefaultWBurstTarget {
		t.Fatalf("expected impulsive jump to burst target %d, got %d", DefaultWBurstTarget, w)
	}

	c.OnQueueEmpty()
	if w := c.CurrentWindow(); w != DefaultWBaseline {
		t.Fatalf("expected drop back to baseline %d after queue empties, got %d", DefaultWBaseline, w)
	}
}

func TestCongestionController_ErrorAbortsBurstAndPenalizesCeiling(t *testing.T) {
	c := NewCongestionController()
	c.OnQueueNonEmpty()
	if !c.InBurst() {
		t.Fatal("expected to be in burst")
	}

	c.OnTimeoutOrServerError()
	if c.InBurst() {
		t.Fatal("any error during a burst must abort it immediately")
	}
	if c.CurrentWindow() != DefaultWBaseline {
		t.Fatalf("window should drop to baseline after burst abort, got %d", c.CurrentWindow())
	}

	// Next burst's ceiling should be penalized (lower than the default target).
	c.OnQueueNonEmpty()
	if w := c.CurrentWindow(); w >= DefaultWBurstTarget {
		t.Fatalf("expected penalized (lower) burst ceiling after prior error, got %d (target was %d)", w, DefaultWBurstTarget)
	}
}

func TestCongestionController_IncompleteResponseShrinksBlockNotWindow(t *testing.T) {
	c := NewCongestionController()
	startBlock := c.CurrentBlockSize()
	startWindow := c.CurrentWindow()

	c.OnIncompleteResponse()

	if c.CurrentBlockSize() >= startBlock {
		t.Fatalf("block size should shrink on incomplete response: before=%d after=%d", startBlock, c.CurrentBlockSize())
	}
	if c.CurrentWindow() != startWindow {
		t.Fatalf("window must NOT change on incomplete response (only block size should), before=%d after=%d", startWindow, c.CurrentWindow())
	}
}

func TestCongestionController_BlockSizeNeverExceedsSoftMax(t *testing.T) {
	c := NewCongestionController()
	for i := 0; i < 10000; i++ {
		c.OnSuccess(50 * time.Millisecond)
	}
	if c.CurrentBlockSize() > c.BlockSoftMax {
		t.Fatalf("block size must never exceed soft max %d, got %d", c.BlockSoftMax, c.CurrentBlockSize())
	}
}

func TestReconnectState_GraceClosesEarlyOnConfirmation(t *testing.T) {
	r := NewReconnectState()
	r.StartGrace()

	if !r.Status().Active {
		t.Fatal("grace period should be active immediately after start")
	}
	if !r.ShouldSendRedundant() {
		t.Fatal("should send redundant frames while unconfirmed and in grace")
	}

	r.ConfirmKey()
	st := r.Status()
	if st.Active || !st.Confirmed {
		t.Fatalf("grace period should close immediately on confirmation, got %+v", st)
	}
	if r.ShouldSendRedundant() {
		t.Fatal("should stop sending redundant frames once key is confirmed")
	}
}

func TestReconnectState_RedundantBudgetExhausts(t *testing.T) {
	r := NewReconnectState()
	r.StartGrace()
	for i := 0; i < DefaultRedundantCount; i++ {
		if !r.ShouldSendRedundant() {
			t.Fatalf("expected redundant send #%d to be allowed", i)
		}
		r.MarkRedundantSent()
	}
	if r.ShouldSendRedundant() {
		t.Fatal("redundant budget should be exhausted after DefaultRedundantCount sends")
	}
}

func TestSession_EndToEndEncodeDecode(t *testing.T) {
	sess := NewSession(0xDEADBEEF)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 3)
	}
	sess.CompleteHandshake(0xA1B2C3D4, key)

	wire, err := sess.EncodeOutgoing([]byte("hello"), proto.FlagData)
	if err != nil {
		t.Fatalf("EncodeOutgoing: %v", err)
	}

	// Decode with a fresh session sharing the same key/connection_id,
	// simulating the peer.
	peer := NewSession(0xDEADBEEF)
	peer.CompleteHandshake(0xA1B2C3D4, key)

	result, err := peer.DecodeIncoming(wire)
	if err != nil {
		t.Fatalf("DecodeIncoming: %v", err)
	}
	if !result.Accepted || result.Replay {
		t.Fatalf("expected frame to be accepted, got %+v", result)
	}
	if len(result.Ready) != 1 || string(result.Ready[0]) != "hello" {
		t.Fatalf("expected payload 'hello' ready for delivery, got %v", result.Ready)
	}

	// Replaying the exact same wire bytes must be rejected.
	replay, err := peer.DecodeIncoming(wire)
	if err != nil {
		t.Fatalf("DecodeIncoming (replay): %v", err)
	}
	if replay.Accepted || !replay.Replay {
		t.Fatalf("expected replay to be rejected, got %+v", replay)
	}
}
