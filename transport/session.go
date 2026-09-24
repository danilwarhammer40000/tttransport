package transport

import (
	"sync"
	"sync/atomic"
	"time"

	"turboflare-transport/proto"
)

// State is the session's lifecycle state.
type State int

const (
	StateNew State = iota
	StateHandshaking
	StateActive
	StateReconnecting
	StateClosed
)

func (s State) String() string {
	switch s {
	case StateNew:
		return "NEW"
	case StateHandshaking:
		return "HANDSHAKING"
	case StateActive:
		return "ACTIVE"
	case StateReconnecting:
		return "RECONNECTING"
	case StateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// Session holds all per-connection state on one side (client or server
// use the same struct symmetrically). It is the integration point for
// proto/ (wire format), the congestion controller, the reorder buffer,
// and the anti-replay window.
type Session struct {
	mu sync.RWMutex

	DeviceID     uint64
	ConnectionID uint32
	SessionKey   []byte
	State        State

	// sendCounter is the per-session, per-key nonce counter used for
	// OUTGOING frames. Must never repeat for a given SessionKey -- reset
	// to 0 only when SessionKey itself changes (new handshake/reconnect).
	sendCounter uint32

	// sendSequence is the application-level byte-stream sequence number
	// for outgoing data (distinct from the nonce counter -- see
	// proto/frame.go CHANGELOG note on why these had to be split apart).
	sendSequence uint32

	replay  *ReplayWindow
	reorder *ReorderBuffer

	Congestion *CongestionController
	Reconnect  *ReconnectState

	lastActivity time.Time
}

// NewSession creates a fresh, not-yet-handshaken session for a given
// device_id. ConnectionID/SessionKey are filled in once the handshake
// completes (see CompleteHandshake).
func NewSession(deviceID uint64) *Session {
	return &Session{
		DeviceID:     deviceID,
		State:        StateNew,
		replay:       NewReplayWindow(),
		reorder:      NewReorderBuffer(0),
		Congestion:   NewCongestionController(),
		Reconnect:    NewReconnectState(),
		lastActivity: time.Now(),
	}
}

// CompleteHandshake installs a freshly derived session_key (and, on a
// brand-new session, a server-assigned connection_id). Per the fixed
// design this ALWAYS resets the nonce counter and anti-replay window to
// zero, because a new session_key means the (connection_id, counter)
// nonce space starts over and old high-water marks from a prior key are
// meaningless (and dangerous to compare against).
func (s *Session) CompleteHandshake(connectionID uint32, sessionKey []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ConnectionID = connectionID
	s.SessionKey = sessionKey
	s.sendCounter = 0
	s.replay.Reset()
	s.State = StateActive
	s.lastActivity = time.Now()
}

// NextSendCounter atomically hands out the next nonce counter value for
// an outgoing frame under the CURRENT session key. Safe for concurrent
// callers (parallel burst transactions).
func (s *Session) NextSendCounter() uint32 {
	return atomic.AddUint32(&s.sendCounter, 1) - 1
}

// NextSendSequence atomically hands out the next application-level
// sequence number for outgoing payload data.
func (s *Session) NextSendSequence() uint32 {
	return atomic.AddUint32(&s.sendSequence, 1) - 1
}

// EncodeOutgoing builds a ready-to-send wire frame for a chunk of
// application payload, pulling counter/sequence/session key from
// current session state.
func (s *Session) EncodeOutgoing(payload []byte, flags proto.Flags) ([]byte, error) {
	s.mu.RLock()
	key := s.SessionKey
	connID := s.ConnectionID
	s.mu.RUnlock()

	seq := s.NextSendSequence()
	ctr := s.NextSendCounter()

	f := proto.DataFrame{
		ConnectionID: connID,
		Sequence:     seq,
		Flags:        flags | proto.FlagData,
		Payload:      payload,
	}
	return proto.EncodeDataFrame(key, ctr, f)
}

// DecodeIncomingResult reports what happened to a received wire frame.
type DecodeIncomingResult struct {
	Accepted bool
	Replay   bool
	Ready    [][]byte // payloads now ready for in-order application delivery
	Frame    proto.DataFrame
}

// DecodeIncoming processes one received wire frame: verifies AEAD
// integrity + freshness (anti-replay), then feeds it into the reorder
// buffer for in-order delivery.
func (s *Session) DecodeIncoming(wire []byte) (DecodeIncomingResult, error) {
	s.mu.RLock()
	key := s.SessionKey
	connID := s.ConnectionID
	s.mu.RUnlock()

	frame, counter, err := proto.DecodeDataFrame(key, connID, wire)
	if err != nil {
		return DecodeIncomingResult{}, err
	}

	if !s.replay.CheckAndMark(counter) {
		return DecodeIncomingResult{Accepted: false, Replay: true, Frame: frame}, nil
	}

	s.mu.Lock()
	s.lastActivity = time.Now()
	s.mu.Unlock()

	ready := s.reorder.Insert(frame.Sequence, frame.Payload)
	return DecodeIncomingResult{Accepted: true, Ready: ready, Frame: frame}, nil
}

func (s *Session) LastActivity() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastActivity
}

func (s *Session) SetState(st State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.State = st
}

func (s *Session) GetState() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.State
}
