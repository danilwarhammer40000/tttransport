// Package server implements the origin-side HTTP endpoints for the
// TurboFlare transport prototype. Deliberately net/http + stdlib TLS
// for now (Stage 3) -- fingerprint spoofing (uTLS) is a CLIENT-side
// concern per PROTOCOL.md §3 and doesn't apply to the server.
//
// STAGE 3.1 UPDATE: this used to be a pure echo server (delivered
// payloads were mirrored straight back onto the same connection's
// outbox). It now does real internet egress: the FIRST payload of a
// session is treated as a plaintext CONNECT command ("host:port"), the
// server dials that target over real TCP, and every subsequent payload
// is forwarded raw to that socket -- with the socket's responses queued
// back through the exact same sequence/ACK/congestion-aware framing
// (transport.Session), unchanged. Only what happens to the decrypted
// payload after DecodeIncoming changed; the wire protocol itself is
// untouched.
package server

import (
	"bufio"
	"crypto/ecdh"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"turboflare-transport/proto"
	"turboflare-transport/transport"
)

// connState bundles the protocol session with the real outbound TCP
// connection it forwards to, once one has been established via the
// CONNECT command.
type connState struct {
	sess *transport.Session

	mu         sync.Mutex
	outbound   net.Conn
	connecting bool // guards against a racing duplicate CONNECT
	targetAddr string
}

// Server holds all origin-side state: the static X25519 identity key,
// the token/device binding store, and the live session table.
type Server struct {
	StaticPriv *ecdh.PrivateKey
	Tokens     *TokenStore

	mu         sync.Mutex
	conns      map[uint32]*connState
	outbox     map[uint32][][]byte // queued outgoing wire frames per connection, for GET /pull
	nextConnID uint32

	// AllowedTargets, if non-empty, restricts which host:port a client
	// may CONNECT to (host or host:port entries). Leave empty to allow
	// any target -- fine for a personal research prototype talking to
	// yourself, but an open relay to arbitrary internet hosts is a
	// meaningful responsibility to take on, so this exists as an easy
	// place to add a restriction later without changing the protocol.
	AllowedTargets map[string]bool

	// DialTimeout bounds how long CONNECT waits for the outbound TCP
	// handshake before giving up.
	DialTimeout time.Duration

	Logger *log.Logger
}

func New(staticPriv *ecdh.PrivateKey, tokens *TokenStore) *Server {
	return &Server{
		StaticPriv:  staticPriv,
		Tokens:      tokens,
		conns:       make(map[uint32]*connState),
		outbox:      make(map[uint32][][]byte),
		nextConnID:  1, // connection_id=0 is reserved (see proto/frame.go bugfix note)
		DialTimeout: 10 * time.Second,
		Logger:      log.Default(),
	}
}

const HKDFInfo = "turboflare-transport-v1"

const HeaderProvisionToken = "X-Provision-Token"

// Handler returns the http.Handler exposing all endpoints, ready to be
// reverse-proxied by Caddy (see server/caddy/Caddyfile).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleHealth)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/v1/open", s.handleOpen)
	mux.HandleFunc("/api/v1/push", s.handlePush)
	mux.HandleFunc("/api/v1/pull", s.handlePull)
	return mux
}

// handleHealth answers TurboFlare's (or any CDN's) origin health check
// with a plain 200 "OK" on "/" and "/health" specifically. Any other
// unmatched path still falls through to the same generic 404 the API
// handlers use -- this keeps the "don't reveal the protocol via error
// responses" property (§4) for everything except the two paths a health
// checker actually needs.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" || r.URL.Path == "/health" {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
		return
	}
	http.NotFound(w, r)
}

// handleOpen processes a handshake frame (new session or reconnect).
func (s *Server) handleOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	token := r.Header.Get(HeaderProvisionToken)
	if token == "" {
		http.NotFound(w, r)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, int64(proto.HandshakeWireSize)))
	if err != nil || len(body) != proto.HandshakeWireSize {
		http.NotFound(w, r)
		return
	}

	plaintext, sessionKey, _, err := proto.DecodeHandshake(body, s.StaticPriv, HKDFInfo)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	bindResult := s.Tokens.TryBind(token, plaintext.DeviceID)
	if bindResult != BindAccepted {
		http.NotFound(w, r)
		return
	}
	s.Tokens.Touch(token)

	s.mu.Lock()
	var cs *connState
	var connID uint32
	keyConfirmed := false

	if plaintext.ConnectionID != 0 {
		if existing, ok := s.conns[plaintext.ConnectionID]; ok && existing.sess.DeviceID == plaintext.DeviceID {
			cs = existing
			connID = plaintext.ConnectionID
			keyConfirmed = true
		}
	}
	if cs == nil {
		connID = atomic.AddUint32(&s.nextConnID, 1) - 1
		cs = &connState{sess: transport.NewSession(plaintext.DeviceID)}
		s.conns[connID] = cs
	}
	s.mu.Unlock()

	cs.sess.CompleteHandshake(connID, sessionKey)

	resp := make([]byte, 5)
	binary.BigEndian.PutUint32(resp[0:4], connID)
	if keyConfirmed {
		resp[4] = byte(proto.FlagKeyConfirmed)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// handlePush accepts one or more data frames from the client (upload
// channel). Body is a sequence of length-prefixed wire frames:
// [uint16 length][frame bytes]...
//
// Delivered (in-order, deduplicated) payloads are handed to
// forwardPayload: the first one per session is a CONNECT command, every
// one after that is raw bytes written straight to the outbound socket.
func (s *Server) handlePush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	connID, cs, ok := s.connStateFromRequest(r)
	if !ok {
		http.NotFound(w, r)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20)) // 8 MiB safety cap
	if err != nil {
		http.Error(w, "read error", http.StatusBadGateway)
		return
	}

	var delivered [][]byte
	offset := 0
	for offset+2 <= len(body) {
		frameLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
		offset += 2
		if offset+frameLen > len(body) {
			break
		}
		wire := body[offset : offset+frameLen]
		offset += frameLen

		result, err := cs.sess.DecodeIncoming(wire)
		if err != nil {
			continue // malformed/tampered frame -- drop, don't error the whole batch
		}
		if !result.Accepted {
			continue // replay -- silently absorbed, per anti-replay design
		}
		delivered = append(delivered, result.Ready...)
	}

	for _, payload := range delivered {
		s.forwardPayload(connID, cs, payload)
	}

	w.WriteHeader(http.StatusOK)
}

// forwardPayload handles one in-order payload for a session: if there's
// no outbound connection yet, the payload IS the CONNECT command
// ("host:port", plaintext ASCII). Otherwise it's raw bytes to write to
// the already-established outbound socket.
//
// KNOWN LIMITATION: dialAndPumpAsync connects in the background, so if
// the client pushes data immediately after CONNECT in the SAME batch
// (before the dial completes), that data is silently dropped -- the
// client-side contract for now is: push CONNECT, poll /pull until "OK
// CONNECTED" (or an "ERROR..." payload) arrives, THEN start pushing
// real data. A production version would buffer pre-connect writes
// instead of dropping them; left as a follow-up since it doesn't affect
// correctness for a client that waits for confirmation, which is what
// client.Client's intended usage pattern already does.
func (s *Server) forwardPayload(connID uint32, cs *connState, payload []byte) {
	cs.mu.Lock()
	if cs.outbound == nil {
		if cs.connecting {
			cs.mu.Unlock()
			return // a CONNECT is already in flight for this session
		}
		cs.connecting = true
		target := strings.TrimSpace(string(payload))
		cs.targetAddr = target
		cs.mu.Unlock()

		s.dialAndPumpAsync(connID, cs, target)
		return
	}
	conn := cs.outbound
	cs.mu.Unlock()

	if _, err := conn.Write(payload); err != nil {
		s.Logger.Printf("forwardPayload: write to %s failed: %v", cs.targetAddr, err)
		s.closeOutbound(connID, cs)
	}
}

// dialAndPumpAsync validates the requested target, dials it, and starts
// a goroutine relaying bytes FROM the outbound socket back into this
// session's outbox (i.e. what GET /pull will return). Runs
// asynchronously so a slow/hanging CONNECT doesn't block the HTTP
// response to the client's push.
func (s *Server) dialAndPumpAsync(connID uint32, cs *connState, target string) {
	go func() {
		if err := s.validateTarget(target); err != nil {
			s.Logger.Printf("dialAndPumpAsync: target %q rejected: %v", target, err)
			s.queueOutgoing(connID, cs.sess, []byte(fmt.Sprintf("ERROR: %v", err)))
			cs.mu.Lock()
			cs.connecting = false
			cs.mu.Unlock()
			return
		}

		conn, err := net.DialTimeout("tcp", target, s.DialTimeout)
		if err != nil {
			s.Logger.Printf("dialAndPumpAsync: dial %q failed: %v", target, err)
			s.queueOutgoing(connID, cs.sess, []byte(fmt.Sprintf("ERROR: dial failed: %v", err)))
			cs.mu.Lock()
			cs.connecting = false
			cs.mu.Unlock()
			return
		}

		cs.mu.Lock()
		cs.outbound = conn
		cs.connecting = false
		cs.mu.Unlock()

		s.queueOutgoing(connID, cs.sess, []byte("OK CONNECTED"))
		s.pumpOutboundToSession(connID, cs, conn)
	}()
}

// validateTarget applies the optional allowlist. Empty allowlist means
// "allow anything" -- see the AllowedTargets doc comment on Server.
func (s *Server) validateTarget(target string) error {
	if len(s.AllowedTargets) == 0 {
		return nil
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("invalid target %q: %w", target, err)
	}
	if !s.AllowedTargets[host] && !s.AllowedTargets[target] {
		return fmt.Errorf("target %q not in allowlist", target)
	}
	return nil
}

// pumpOutboundToSession reads from the real TCP socket and queues each
// chunk as an outgoing DataFrame for the client's next /pull, until the
// socket closes or errors.
func (s *Server) pumpOutboundToSession(connID uint32, cs *connState, conn net.Conn) {
	reader := bufio.NewReaderSize(conn, 32*1024)
	buf := make([]byte, 16*1024) // matches the protocol's conservative target block size (§1-2)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			s.queueOutgoing(connID, cs.sess, chunk)
		}
		if err != nil {
			if err != io.EOF {
				s.Logger.Printf("pumpOutboundToSession: read error on %s: %v", cs.targetAddr, err)
			}
			s.closeOutbound(connID, cs)
			return
		}
	}
}

func (s *Server) closeOutbound(connID uint32, cs *connState) {
	cs.mu.Lock()
	conn := cs.outbound
	cs.outbound = nil
	cs.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	_ = connID
}

// handlePull implements the polling download channel (per the original
// research §23: GET /pull?from=N rather than an infinite response
// stream, since the CDN did not reliably support the latter).
func (s *Server) handlePull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	connID, _, ok := s.connStateFromRequest(r)
	if !ok {
		http.NotFound(w, r)
		return
	}

	s.mu.Lock()
	frames := s.outbox[connID]
	s.outbox[connID] = nil
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	for _, f := range frames {
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(f)))
		_, _ = w.Write(lenBuf[:])
		_, _ = w.Write(f)
	}
}

// queueOutgoing encodes payload as a DataFrame under sess and appends it
// to connID's outbox for the next /pull.
func (s *Server) queueOutgoing(connID uint32, sess *transport.Session, payload []byte) {
	wire, err := sess.EncodeOutgoing(payload, 0)
	if err != nil {
		s.Logger.Printf("queueOutgoing: encode error: %v", err)
		return
	}
	s.mu.Lock()
	s.outbox[connID] = append(s.outbox[connID], wire)
	s.mu.Unlock()
}

// connStateFromRequest resolves the connection_id header to a live
// connState. connection_id is sent as a plain header for push/pull
// (unlike the handshake, these are already inside an established,
// key-authenticated session -- the AEAD tag on each frame is what
// actually authenticates the traffic, the header is just routing).
func (s *Server) connStateFromRequest(r *http.Request) (uint32, *connState, bool) {
	raw := r.Header.Get("X-Connection-Id")
	if len(raw) != 8 { // 4 bytes hex-encoded
		return 0, nil, false
	}
	idBytes, err := hex.DecodeString(raw)
	if err != nil {
		return 0, nil, false
	}
	connID := binary.BigEndian.Uint32(idBytes)
	s.mu.Lock()
	cs, ok := s.conns[connID]
	s.mu.Unlock()
	if !ok {
		return 0, nil, false
	}
	return connID, cs, true
}
