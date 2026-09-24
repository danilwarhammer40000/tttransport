package proto

import (
	"crypto/ecdh"
	"encoding/binary"
)

// Flags is a bitmask carried in every frame's plaintext header.
// Multiple flags may be combined (e.g. DATA|ACK for a piggy-backed ack).
type Flags uint8

const (
	FlagOpen  Flags = 1 << iota // 0x01 - session open / handshake
	FlagData                    // 0x02 - carries payload
	FlagAck                     // 0x04 - carries an acknowledgement
	FlagFin                     // 0x08 - graceful stream/session close
	FlagReset                   // 0x10 - abrupt close (error)
	FlagPing                    // 0x20 - keepalive probe
	FlagPong                    // 0x40 - keepalive reply
	// bit 0x80 reserved for future use (e.g. "new key confirmed" signal
	// used during reconnect, per the fixed reconnect design).
	FlagKeyConfirmed
)

// -----------------------------------------------------------------------
// Handshake frame (first frame of a session, and every reconnect).
//
// Wire layout (fixed in PROTOCOL.md §0):
//
//	eph_pub      32B   X25519 ephemeral public key, cleartext
//	nonce        8B    explicit monotonic counter, cleartext, starts at 0
//	                    for THIS session_key (never reused across keys)
//	ciphertext   29B   AES-256-GCM seal of the 13-byte plaintext below,
//	                    tag included (13 + 16 = 29)
//	  -> device_id      8B
//	  -> connection_id  4B   (0x00000000 for a brand-new session)
//	  -> flags          1B
//
// Total wire size: 32 + 8 + 29 = 69 bytes.
// -----------------------------------------------------------------------

const (
	HandshakePlaintextSize = 8 + 4 + 1 // device_id + connection_id + flags
	HandshakeWireSize      = X25519KeySize + 8 + HandshakePlaintextSize + AuthTagSize
)

type HandshakePlaintext struct {
	DeviceID     uint64
	ConnectionID uint32 // 0 => requesting a brand-new session
	Flags        Flags
}

func (p HandshakePlaintext) encode() []byte {
	buf := make([]byte, HandshakePlaintextSize)
	binary.BigEndian.PutUint64(buf[0:8], p.DeviceID)
	binary.BigEndian.PutUint32(buf[8:12], p.ConnectionID)
	buf[12] = byte(p.Flags)
	return buf
}

func decodeHandshakePlaintext(buf []byte) (HandshakePlaintext, error) {
	if len(buf) != HandshakePlaintextSize {
		return HandshakePlaintext{}, ErrShortBuffer
	}
	return HandshakePlaintext{
		DeviceID:     binary.BigEndian.Uint64(buf[0:8]),
		ConnectionID: binary.BigEndian.Uint32(buf[8:12]),
		Flags:        Flags(buf[12]),
	}, nil
}

// EncodeHandshake builds the full 69-byte wire representation of a
// handshake frame. sharedSecretFn performs the X25519 ECDH given the
// peer's static/ephemeral public key as appropriate for caller's role;
// callers on the client side pass serverStaticPub, callers on the
// server side pass the received ephPub.
func EncodeHandshake(ephPriv *ecdh.PrivateKey, peerPub *ecdh.PublicKey, nonceCounter uint64, plaintext HandshakePlaintext, hkdfInfo string) (wire []byte, sessionKey []byte, err error) {
	shared, err := ephPriv.ECDH(peerPub)
	if err != nil {
		return nil, nil, err
	}

	ephPubRaw := ephPriv.PublicKey().Bytes() // 32 bytes

	var nonceBuf [8]byte
	binary.BigEndian.PutUint64(nonceBuf[:], nonceCounter)

	// salt = client's ephemeral public key, per the fixed design
	// (DeriveSessionKey salt=client_nonce -- here "client_nonce" refers
	// to the client's contribution to the handshake, i.e. its ephemeral
	// pubkey, which both sides already have at this point).
	sessionKey, err = DeriveSessionKey(shared, ephPubRaw, hkdfInfo)
	if err != nil {
		return nil, nil, err
	}

	// BUGFIX (found while building server/client in Stage 3): the
	// handshake ciphertext's GCM nonce must use a FIXED placeholder
	// connection_id (0), never the real target connection_id -- the
	// receiver cannot know the real connection_id before decrypting, so
	// encode/decode would disagree on reconnect (nonzero connection_id)
	// if encode used the real value here. The handshake's own namespace
	// (separate HTTP endpoint from data frames) makes reusing "0" safe;
	// it never collides with data-frame nonces for connection_id 0,
	// since no session is ever assigned connection_id=0 by the server.
	gcmNonce := BuildNonce(0, nonceCounter)
	sealed, err := Seal(sessionKey, gcmNonce, plaintext.encode())
	if err != nil {
		return nil, nil, err
	}

	wire = make([]byte, 0, HandshakeWireSize)
	wire = append(wire, ephPubRaw...)
	wire = append(wire, nonceBuf[:]...)
	wire = append(wire, sealed...)
	return wire, sessionKey, nil
}

// DecodeHandshake parses and decrypts a handshake wire frame. localPriv
// is the receiver's own private key (server's static key when the
// receiver is the server; not used symmetrically on the client side --
// see DecodeHandshakeAsClient for that direction).
func DecodeHandshake(wire []byte, localPriv *ecdh.PrivateKey, hkdfInfo string) (plaintext HandshakePlaintext, sessionKey []byte, ephPub *ecdh.PublicKey, err error) {
	if len(wire) != HandshakeWireSize {
		return HandshakePlaintext{}, nil, nil, ErrShortBuffer
	}

	ephPubRaw := wire[0:32]
	nonceCounter := binary.BigEndian.Uint64(wire[32:40])
	sealed := wire[40:]

	ephPub, err = LoadX25519PublicKey(ephPubRaw)
	if err != nil {
		return HandshakePlaintext{}, nil, nil, err
	}

	shared, err := localPriv.ECDH(ephPub)
	if err != nil {
		return HandshakePlaintext{}, nil, nil, err
	}

	sessionKey, err = DeriveSessionKey(shared, ephPubRaw, hkdfInfo)
	if err != nil {
		return HandshakePlaintext{}, nil, nil, err
	}

	// connection_id is not known before decryption, so try nonce with
	// connection_id=0 first (new session); caller retries with the
	// known connection_id on reconnect (see DecodeHandshakeReconnect).
	gcmNonce := BuildNonce(0, nonceCounter)
	pt, err := Open(sessionKey, gcmNonce, sealed)
	if err != nil {
		return HandshakePlaintext{}, nil, nil, err
	}

	plaintext, err = decodeHandshakePlaintext(pt)
	if err != nil {
		return HandshakePlaintext{}, nil, nil, err
	}
	return plaintext, sessionKey, ephPub, nil
}

// -----------------------------------------------------------------------
// Data frame (every frame after a completed handshake).
//
// CHANGELOG NOTE (fixed during Stage 2 build): the original Stage 1
// design assumed the nonce counter never needs to be sent, since both
// peers "track it in sync". That assumption breaks under the CDN's own
// documented behavior (research §14/§19): parallel HTTP transactions can
// COMPLETE out of order. A receiver cannot know which counter to try
// for a given ciphertext without either buffering-and-guessing or being
// told directly. Fix: nonce_counter is now an explicit 4-byte cleartext
// field prefixing the sealed blob, like the handshake frame already
// does. This makes every data frame independently decryptable regardless
// of arrival order, and keeps sequence-based reassembly (below) a purely
// separate, higher-level concern (ordering for delivery, not for
// decryption). Replay protection now lives in transport/replay.go as an
// explicit sliding-window check over received nonce_counter values,
// since the wire no longer implicitly enforces "next counter must be
// exactly N".
//
// Wire layout:
//
//	nonce_counter 4B   cleartext, unique per (connection_id, session_key)
//	ciphertext    var  AES-256-GCM seal of the plaintext below, tag included
//	  -> connection_id  4B
//	  -> stream_id      2B   (0 if multiplexing unused)
//	  -> sequence       4B
//	  -> ack            4B
//	  -> flags          1B
//	  -> payload_length 2B
//	  -> payload        var
//
// Fixed per-frame overhead (excluding payload):
// 4 (nonce_counter) + 4+2+4+4+1+2 (header) + 16 (tag) = 37 bytes.
// (Stage 1 originally stated 33 bytes assuming an implicit counter;
// revised to 37 here for correctness. Still lean relative to VLESS.)
// -----------------------------------------------------------------------

const NonceCounterFieldSize = 4
const DataHeaderSize = 4 + 2 + 4 + 4 + 1 + 2                          // = 17, before payload
const DataFrameOverhead = NonceCounterFieldSize + DataHeaderSize + AuthTagSize // = 37

type DataFrame struct {
	ConnectionID uint32
	StreamID     uint16
	Sequence     uint32
	Ack          uint32
	Flags        Flags
	Payload      []byte
}

func (f DataFrame) encodePlaintext() []byte {
	buf := make([]byte, DataHeaderSize+len(f.Payload))
	binary.BigEndian.PutUint32(buf[0:4], f.ConnectionID)
	binary.BigEndian.PutUint16(buf[4:6], f.StreamID)
	binary.BigEndian.PutUint32(buf[6:10], f.Sequence)
	binary.BigEndian.PutUint32(buf[10:14], f.Ack)
	buf[14] = byte(f.Flags)
	binary.BigEndian.PutUint16(buf[15:17], uint16(len(f.Payload)))
	copy(buf[17:], f.Payload)
	return buf
}

func decodeDataPlaintext(buf []byte) (DataFrame, error) {
	if len(buf) < DataHeaderSize {
		return DataFrame{}, ErrShortBuffer
	}
	payloadLen := int(binary.BigEndian.Uint16(buf[15:17]))
	if len(buf) != DataHeaderSize+payloadLen {
		return DataFrame{}, ErrShortBuffer
	}
	f := DataFrame{
		ConnectionID: binary.BigEndian.Uint32(buf[0:4]),
		StreamID:     binary.BigEndian.Uint16(buf[4:6]),
		Sequence:     binary.BigEndian.Uint32(buf[6:10]),
		Ack:          binary.BigEndian.Uint32(buf[10:14]),
		Flags:        Flags(buf[14]),
	}
	f.Payload = make([]byte, payloadLen)
	copy(f.Payload, buf[17:])
	return f, nil
}

// EncodeDataFrame seals a DataFrame for the wire. counter must be unique
// for this (connection_id, session_key) pair -- never reused. The
// session state machine (transport/session.go) hands out a fresh value
// from an atomic per-session counter for every call.
func EncodeDataFrame(sessionKey []byte, counter uint32, f DataFrame) (wire []byte, err error) {
	nonce := BuildNonce(f.ConnectionID, uint64(counter))
	sealed, err := Seal(sessionKey, nonce, f.encodePlaintext())
	if err != nil {
		return nil, err
	}
	wire = make([]byte, 0, NonceCounterFieldSize+len(sealed))
	var ctrBuf [NonceCounterFieldSize]byte
	binary.BigEndian.PutUint32(ctrBuf[:], counter)
	wire = append(wire, ctrBuf[:]...)
	wire = append(wire, sealed...)
	return wire, nil
}

// DecodeDataFrame reads the explicit nonce_counter prefix and opens the
// sealed data frame given the session key and connection_id. Callers
// MUST run the returned counter through the anti-replay window
// (transport/replay.go) before trusting the frame -- this function only
// verifies AEAD integrity, not freshness.
func DecodeDataFrame(sessionKey []byte, connectionID uint32, wire []byte) (frame DataFrame, counter uint32, err error) {
	if len(wire) < NonceCounterFieldSize {
		return DataFrame{}, 0, ErrShortBuffer
	}
	counter = binary.BigEndian.Uint32(wire[0:NonceCounterFieldSize])
	sealed := wire[NonceCounterFieldSize:]

	nonce := BuildNonce(connectionID, uint64(counter))
	pt, err := Open(sessionKey, nonce, sealed)
	if err != nil {
		return DataFrame{}, 0, err
	}
	frame, err = decodeDataPlaintext(pt)
	if err != nil {
		return DataFrame{}, 0, err
	}
	return frame, counter, nil
}
