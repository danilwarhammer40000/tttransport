// Package client implements the client-side orchestration for the
// TurboFlare transport prototype: handshake (initial + reconnect),
// upload (push), and polling download (pull).
//
// Stage 3 note: uses net/http's default stdlib TLS client. Swapping in
// the uTLS-based fingerprint layer (PROTOCOL.md §3) is a drop-in
// replacement of the http.Client's Transport -- see fingerprint/README.md
// for how that plugs in once built (Stage 4).
package client

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"

	"turboflare-transport/proto"
	"turboflare-transport/transport"
)

const HKDFInfo = "turboflare-transport-v1"
const HeaderProvisionToken = "X-Provision-Token"
const HeaderConnectionID = "X-Connection-Id"

type Client struct {
	ServerStaticPub *ecdh.PublicKey
	DeviceID        uint64
	Token           string
	BaseURL         string // e.g. "https://pelevin-art.ru"
	HTTPClient      *http.Client

	Session *transport.Session
}

func New(baseURL string, serverStaticPub *ecdh.PublicKey, deviceID uint64, token string) *Client {
	return &Client{
		ServerStaticPub: serverStaticPub,
		DeviceID:        deviceID,
		Token:           token,
		BaseURL:         baseURL,
		HTTPClient:      http.DefaultClient,
		Session:         transport.NewSession(deviceID),
	}
}

// Open performs the initial handshake for a brand-new session.
func (c *Client) Open() error {
	return c.doHandshake(0)
}

// Reconnect performs a handshake for an EXISTING session (nonzero
// connection_id), and starts the grace-period bookkeeping per the fixed
// reconnect design. Call this after detecting a network interface
// change (wifi<->LTE).
func (c *Client) Reconnect() error {
	if c.Session.ConnectionID == 0 {
		return fmt.Errorf("client: Reconnect called with no prior session (call Open first)")
	}
	c.Session.Reconnect.StartGrace()
	return c.doHandshake(c.Session.ConnectionID)
}

func (c *Client) doHandshake(connectionID uint32) error {
	ephPriv, err := proto.GenerateEphemeralKeypair()
	if err != nil {
		return fmt.Errorf("client: generate ephemeral keypair: %w", err)
	}

	plaintext := proto.HandshakePlaintext{
		DeviceID:     c.DeviceID,
		ConnectionID: connectionID,
		Flags:        proto.FlagOpen,
	}

	wire, sessionKey, err := proto.EncodeHandshake(ephPriv, c.ServerStaticPub, 0, plaintext, HKDFInfo)
	if err != nil {
		return fmt.Errorf("client: encode handshake: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/api/v1/open", bytes.NewReader(wire))
	if err != nil {
		return err
	}
	req.Header.Set(HeaderProvisionToken, c.Token)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("client: handshake request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("client: handshake rejected, status=%d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5))
	if err != nil || len(body) != 5 {
		return fmt.Errorf("client: malformed handshake response")
	}

	assignedConnID := binary.BigEndian.Uint32(body[0:4])
	respFlags := proto.Flags(body[4])

	c.Session.CompleteHandshake(assignedConnID, sessionKey)

	if respFlags&proto.FlagKeyConfirmed != 0 {
		c.Session.Reconnect.ConfirmKey()
	}
	return nil
}

// Push sends one payload chunk over the upload channel.
func (c *Client) Push(payload []byte) error {
	wire, err := c.Session.EncodeOutgoing(payload, 0)
	if err != nil {
		return fmt.Errorf("client: encode outgoing: %w", err)
	}

	var buf bytes.Buffer
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(wire)))
	buf.Write(lenBuf[:])
	buf.Write(wire)

	// Redundant send during an active, unconfirmed reconnect grace
	// period, per the fixed design -- dedup on the server side (by
	// sequence, via the reorder buffer) absorbs the duplicates.
	sends := 1
	if c.Session.Reconnect.ShouldSendRedundant() {
		sends = 1 // the SAME encoded wire is what gets duplicated below
	}

	for i := 0; i < sends; i++ {
		if err := c.doPush(buf.Bytes()); err != nil {
			return err
		}
		if c.Session.Reconnect.ShouldSendRedundant() {
			c.Session.Reconnect.MarkRedundantSent()
		}
	}
	return nil
}

func (c *Client) doPush(body []byte) error {
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/api/v1/push", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set(HeaderConnectionID, hex.EncodeToString(connIDBytes(c.Session.ConnectionID)))
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("client: push request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("client: push rejected, status=%d", resp.StatusCode)
	}
	return nil
}

// Pull polls the download channel once and returns any newly-ready
// (in-order, deduplicated) payloads.
func (c *Client) Pull() ([][]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+"/api/v1/pull", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(HeaderConnectionID, hex.EncodeToString(connIDBytes(c.Session.ConnectionID)))

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client: pull request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client: pull rejected, status=%d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var out [][]byte
	offset := 0
	for offset+2 <= len(body) {
		frameLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
		offset += 2
		if offset+frameLen > len(body) {
			break
		}
		wire := body[offset : offset+frameLen]
		offset += frameLen

		result, err := c.Session.DecodeIncoming(wire)
		if err != nil {
			continue
		}
		if result.Accepted {
			out = append(out, result.Ready...)
		}
	}
	return out, nil
}

func connIDBytes(id uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, id)
	return b
}
