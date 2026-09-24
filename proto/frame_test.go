package proto

import (
	"bytes"
	"testing"
)

func TestHandshakeRoundTrip_NewSession(t *testing.T) {
	serverPriv, err := GenerateEphemeralKeypair()
	if err != nil {
		t.Fatalf("server keygen: %v", err)
	}
	serverPub := serverPriv.PublicKey()

	clientPriv, err := GenerateEphemeralKeypair()
	if err != nil {
		t.Fatalf("client keygen: %v", err)
	}

	want := HandshakePlaintext{
		DeviceID:     0xAABBCCDDEEFF0011,
		ConnectionID: 0, // brand-new session
		Flags:        FlagOpen,
	}

	wire, clientSessionKey, err := EncodeHandshake(clientPriv, serverPub, 0, want, "turboflare-transport-v1")
	if err != nil {
		t.Fatalf("EncodeHandshake: %v", err)
	}

	if len(wire) != HandshakeWireSize {
		t.Fatalf("handshake wire size = %d, want %d (69 bytes per PROTOCOL.md)", len(wire), HandshakeWireSize)
	}

	got, serverSessionKey, ephPub, err := DecodeHandshake(wire, serverPriv, "turboflare-transport-v1")
	if err != nil {
		t.Fatalf("DecodeHandshake: %v", err)
	}

	if !bytes.Equal(clientSessionKey, serverSessionKey) {
		t.Fatalf("session keys diverged: client=%x server=%x", clientSessionKey, serverSessionKey)
	}
	if got != want {
		t.Fatalf("plaintext mismatch: got %+v, want %+v", got, want)
	}
	if !bytes.Equal(ephPub.Bytes(), clientPriv.PublicKey().Bytes()) {
		t.Fatalf("recovered ephemeral pubkey does not match client's")
	}
}

func TestHandshakeRoundTrip_Reconnect(t *testing.T) {
	// Regression test for the nonce-placeholder bugfix: a reconnect
	// handshake carries a NONZERO connection_id in its plaintext, which
	// must still round-trip correctly (encode and decode must agree on
	// which nonce was used, independent of that connection_id value).
	serverPriv, err := GenerateEphemeralKeypair()
	if err != nil {
		t.Fatalf("server keygen: %v", err)
	}
	clientPriv, err := GenerateEphemeralKeypair()
	if err != nil {
		t.Fatalf("client keygen: %v", err)
	}

	want := HandshakePlaintext{
		DeviceID:     0x1122334455667788,
		ConnectionID: 0xA1B2C3D4, // existing session, reconnecting
		Flags:        FlagOpen,
	}

	wire, _, err := EncodeHandshake(clientPriv, serverPriv.PublicKey(), 0, want, "turboflare-transport-v1")
	if err != nil {
		t.Fatalf("EncodeHandshake (reconnect): %v", err)
	}
	got, _, _, err := DecodeHandshake(wire, serverPriv, "turboflare-transport-v1")
	if err != nil {
		t.Fatalf("DecodeHandshake (reconnect): %v", err)
	}
	if got != want {
		t.Fatalf("reconnect plaintext mismatch: got %+v, want %+v", got, want)
	}
}

func TestHandshakeWireSizeConstant(t *testing.T) {
	if HandshakeWireSize != 69 {
		t.Fatalf("HandshakeWireSize = %d, expected 69 per fixed decision", HandshakeWireSize)
	}
}

func TestDataFrameOverheadConstant(t *testing.T) {
	// Revised during Stage 2 (see CHANGELOG.md / frame.go comment):
	// 4 (explicit nonce_counter) + 17 (header) + 16 (tag) = 37 bytes.
	if DataFrameOverhead != 37 {
		t.Fatalf("DataFrameOverhead = %d, expected 37 per revised decision", DataFrameOverhead)
	}
}

func TestDataFrameRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	f := DataFrame{
		ConnectionID: 0xA3F1B2C4,
		StreamID:     0,
		Sequence:     1042,
		Ack:          1041,
		Flags:        FlagData,
		Payload:      []byte("hello turboflare"),
	}

	var counter uint32 = 7
	wire, err := EncodeDataFrame(key, counter, f)
	if err != nil {
		t.Fatalf("EncodeDataFrame: %v", err)
	}

	wantWireLen := DataFrameOverhead + len(f.Payload)
	if len(wire) != wantWireLen {
		t.Fatalf("wire length = %d, want %d", len(wire), wantWireLen)
	}

	got, gotCounter, err := DecodeDataFrame(key, f.ConnectionID, wire)
	if err != nil {
		t.Fatalf("DecodeDataFrame: %v", err)
	}
	if gotCounter != counter {
		t.Fatalf("counter mismatch: got %d, want %d", gotCounter, counter)
	}

	if got.ConnectionID != f.ConnectionID || got.StreamID != f.StreamID ||
		got.Sequence != f.Sequence || got.Ack != f.Ack || got.Flags != f.Flags ||
		!bytes.Equal(got.Payload, f.Payload) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, f)
	}
}

func TestDataFrameOutOfOrderStillDecodes(t *testing.T) {
	// This is exactly the case that broke the Stage 1 implicit-counter
	// design: two frames sent back-to-back, but the SECOND one's HTTP
	// transaction completes first. With an explicit nonce_counter per
	// frame, decode order no longer matters.
	key := make([]byte, 32)
	f1 := DataFrame{ConnectionID: 1, Sequence: 10, Payload: []byte("first")}
	f2 := DataFrame{ConnectionID: 1, Sequence: 11, Payload: []byte("second")}

	wire1, _ := EncodeDataFrame(key, 100, f1)
	wire2, _ := EncodeDataFrame(key, 101, f2)

	got2, ctr2, err := DecodeDataFrame(key, 1, wire2)
	if err != nil {
		t.Fatalf("decode wire2 first: %v", err)
	}
	got1, ctr1, err := DecodeDataFrame(key, 1, wire1)
	if err != nil {
		t.Fatalf("decode wire1 second: %v", err)
	}

	if ctr2 != 101 || ctr1 != 100 {
		t.Fatalf("counters not preserved independently: ctr1=%d ctr2=%d", ctr1, ctr2)
	}
	if got1.Sequence != 10 || got2.Sequence != 11 {
		t.Fatalf("sequence mismatch after out-of-order decode")
	}
}

func TestDataFrameTamperedCiphertextFailsAuth(t *testing.T) {
	key := make([]byte, 32)
	f := DataFrame{ConnectionID: 1, Sequence: 1, Payload: []byte("x")}

	wire, err := EncodeDataFrame(key, 5, f)
	if err != nil {
		t.Fatalf("EncodeDataFrame: %v", err)
	}
	wire[len(wire)-1] ^= 0xFF

	if _, _, err := DecodeDataFrame(key, f.ConnectionID, wire); err != ErrDecryptFailed {
		t.Fatalf("expected ErrDecryptFailed with tampered ciphertext, got %v", err)
	}
}
