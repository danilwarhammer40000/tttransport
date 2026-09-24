// Package proto implements the wire format and cryptographic layer
// for the TurboFlare transport protocol, as fixed in PROTOCOL.md.
//
// Deliberately uses only the Go standard library (crypto/ecdh,
// crypto/aes, crypto/cipher, crypto/hmac, crypto/sha256) so the
// module builds with zero external dependencies.
package proto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

const (
	X25519KeySize = 32
	AuthTagSize   = 16 // AES-256-GCM tag
	GCMNonceSize  = 12 // required by crypto/cipher AEAD for AES-GCM
)

var (
	ErrShortBuffer   = errors.New("proto: buffer too short")
	ErrDecryptFailed = errors.New("proto: decryption/authentication failed")
)

// ---------------------------------------------------------------------
// X25519 ephemeral keypair (client side of the handshake, per §0)
// ---------------------------------------------------------------------

// GenerateEphemeralKeypair creates a fresh X25519 keypair for a single
// handshake. Per the fixed decision: a new session_key is derived from
// a NEW ephemeral keypair on every handshake (initial connect AND every
// reconnect), giving forward secrecy and a fresh nonce counter each time.
func GenerateEphemeralKeypair() (priv *ecdh.PrivateKey, err error) {
	priv, err = ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// LoadX25519PublicKey parses a 32-byte raw public key (as sent on the wire).
func LoadX25519PublicKey(raw []byte) (*ecdh.PublicKey, error) {
	return ecdh.X25519().NewPublicKey(raw)
}

// LoadX25519PrivateKey parses a 32-byte raw private (server static) key.
func LoadX25519PrivateKey(raw []byte) (*ecdh.PrivateKey, error) {
	return ecdh.X25519().NewPrivateKey(raw)
}

// ---------------------------------------------------------------------
// HKDF-SHA256 (RFC 5869), implemented directly over crypto/hmac since
// golang.org/x/crypto/hkdf is not in the standard library and this
// module intentionally avoids external dependencies.
// ---------------------------------------------------------------------

// hkdfExtract implements HKDF-Extract(salt, ikm) -> pseudorandom key.
func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// hkdfExpand implements HKDF-Expand(prk, info, length) -> output key material.
func hkdfExpand(prk, info []byte, length int) ([]byte, error) {
	hashLen := sha256.Size
	if length > 255*hashLen {
		return nil, errors.New("proto: hkdf expand length too large")
	}
	var (
		out  []byte
		prev []byte
		i    byte = 1
	)
	for len(out) < length {
		mac := hmac.New(sha256.New, prk)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{i})
		prev = mac.Sum(nil)
		out = append(out, prev...)
		i++
	}
	return out[:length], nil
}

// DeriveSessionKey runs full HKDF-SHA256(salt, ikm, info) -> 32-byte key,
// matching the design: session_key = HKDF(shared_secret, salt=client_nonce, info="turboflare-transport-v1").
func DeriveSessionKey(sharedSecret, salt []byte, info string) ([]byte, error) {
	prk := hkdfExtract(salt, sharedSecret)
	return hkdfExpand(prk, []byte(info), 32) // 32 bytes = AES-256 key size
}

// ---------------------------------------------------------------------
// AEAD framing: AES-256-GCM.
//
// Per the fixed design, the nonce for ordinary DATA frames is NEVER
// transmitted on the wire -- both sides track it as a per-session
// monotonic counter, reset to zero on every new session_key (i.e. on
// every handshake / reconnect). Only the initial handshake frame
// carries an explicit 8-byte nonce counter value (see frame.go).
// ---------------------------------------------------------------------

// sessionAEAD wraps a derived key into a ready-to-use cipher.AEAD.
func sessionAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// BuildNonce constructs the 12-byte GCM nonce from the 4-byte connection_id
// and an 8-byte monotonic counter, per the fixed frame format:
//
//	nonce = connection_id (4B) || counter (8B)
//
// This is never sent for DATA frames -- both peers derive it from state
// they already have (connection_id + their tracked counter).
func BuildNonce(connectionID uint32, counter uint64) [GCMNonceSize]byte {
	var nonce [GCMNonceSize]byte
	binary.BigEndian.PutUint32(nonce[0:4], connectionID)
	binary.BigEndian.PutUint64(nonce[4:12], counter)
	return nonce
}

// Seal encrypts+authenticates plaintext under key/nonce, appending the
// 16-byte auth tag. No additional data (AAD) is used at this layer --
// frame-level fields that need integrity protection are placed inside
// the plaintext itself (see frame.go), consistent with the fixed design.
func Seal(key []byte, nonce [GCMNonceSize]byte, plaintext []byte) ([]byte, error) {
	aead, err := sessionAEAD(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce[:], plaintext, nil), nil
}

// Open decrypts+verifies ciphertext (which includes the trailing auth tag)
// under key/nonce.
func Open(key []byte, nonce [GCMNonceSize]byte, ciphertext []byte) ([]byte, error) {
	aead, err := sessionAEAD(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return pt, nil
}

// RandomBytes is a small helper for generating the handshake-frame
// nonce-counter starting value / salts where needed.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}
