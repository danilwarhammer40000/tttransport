// Package observability implements the logging + test-mode design from
// PROTOCOL.md §4. The default EventWriter (JSONLWriter below) is pure
// stdlib and always builds/works offline. A SQLite-backed writer exists
// as an OPTIONAL, isolated subpackage (observability/sqlitewriter) for
// when you want queryable storage -- see its README.
package observability

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Category is one of the per-category logging toggles fixed in
// PROTOCOL.md §4.
type Category string

const (
	CatTxSend          Category = "tx_send"
	CatTxAck           Category = "tx_ack"
	CatTxError         Category = "tx_error"
	CatCongestionWindow Category = "congestion.window_change"
	CatCongestionBlock Category = "congestion.block_change"
	CatCongestionBurst Category = "congestion.burst_events"
	CatHandshake       Category = "connection.handshake"
	CatLifecycle       Category = "connection.lifecycle"
	CatNetworkIface    Category = "network.iface_change"
	CatTokenBinding    Category = "device.token_binding"
	CatTLSProfile      Category = "fingerprint.tls_profile"
	CatHTTP2Settings   Category = "fingerprint.http2_settings"
	CatRawHeaders      Category = "raw.http_headers" // heaviest, separate flag per design
	CatTestMode        Category = "test_mode"
)

// Verbosity is the global override level fixed in §4.
type Verbosity int

const (
	VerbosityDebug Verbosity = iota
	VerbosityInfo
	VerbositySilentExceptErrors
)

// Config holds the per-category toggles. Dev builds default everything
// to true (see DefaultDevConfig).
type Config struct {
	Verbosity  Verbosity
	Categories map[Category]bool
}

func DefaultDevConfig() Config {
	return Config{
		Verbosity: VerbosityDebug,
		Categories: map[Category]bool{
			CatTxSend:           true,
			CatTxAck:            true,
			CatTxError:          true,
			CatCongestionWindow: true,
			CatCongestionBlock:  true,
			CatCongestionBurst:  true,
			CatHandshake:        true,
			CatLifecycle:        true,
			CatNetworkIface:     true,
			CatTokenBinding:     true,
			CatTLSProfile:       true,
			CatHTTP2Settings:    true,
			CatRawHeaders:       true, // heaviest flag, still on by default in DEV build per your instruction
			CatTestMode:         true,
		},
	}
}

func (c Config) enabled(cat Category) bool {
	if c.Verbosity == VerbositySilentExceptErrors && cat != CatTxError {
		return false
	}
	return c.Categories[cat]
}

// EventWriter is the storage abstraction -- JSONLWriter (below) and the
// optional SQLite writer both implement it.
type EventWriter interface {
	Write(event Event) error
	Close() error
}

// Event is one structured log line. Fields carries event-specific data
// as a flat map so the schema doesn't need to change for every new
// event type (matches the "one table, JSON blob column" storage
// decision from §4).
//
// PRIVACY (per the fixed decision): never put session_key, eph_priv/
// eph_pub, device_id in the clear, provisioning tokens in full, or
// payload contents into Fields -- callers should hash/truncate/omit
// those before calling Write. This package does not enforce that
// automatically (it doesn't know which fields are sensitive), so treat
// it as a hard rule for every call site.
type Event struct {
	Timestamp    time.Time
	EventType    string
	Category     Category
	ConnIDPrefix string // short, non-reversible identifier, not the raw connection_id
	Source       string // "traffic" (normal) or "test_mode" -- per §4's tagging requirement
	Fields       map[string]interface{}
}

// Logger is the main entry point used throughout the rest of the
// codebase (transport/, client/, server/) to emit events, gated by
// Config.
type Logger struct {
	mu     sync.Mutex
	cfg    Config
	writer EventWriter
}

func NewLogger(cfg Config, writer EventWriter) *Logger {
	return &Logger{cfg: cfg, writer: writer}
}

func (l *Logger) Log(cat Category, eventType string, connIDPrefix string, source string, fields map[string]interface{}) {
	l.mu.Lock()
	cfg := l.cfg
	l.mu.Unlock()

	if !cfg.enabled(cat) {
		return
	}

	ev := Event{
		Timestamp:    time.Now(),
		EventType:    eventType,
		Category:     cat,
		ConnIDPrefix: connIDPrefix,
		Source:       source,
		Fields:       fields,
	}
	if err := l.writer.Write(ev); err != nil {
		// Logging must never take down the transport -- best-effort,
		// print to stderr as a last resort.
		fmt.Fprintf(os.Stderr, "observability: write error: %v\n", err)
	}
}

func (l *Logger) SetConfig(cfg Config) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cfg = cfg
}

func (l *Logger) Close() error {
	return l.writer.Close()
}

// -----------------------------------------------------------------------
// JSONLWriter: default, stdlib-only backend. One JSON object per line.
// -----------------------------------------------------------------------

type JSONLWriter struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
}

func NewJSONLWriter(path string) (*JSONLWriter, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("observability: open log file: %w", err)
	}
	return &JSONLWriter{file: f, enc: json.NewEncoder(f)}, nil
}

type jsonlLine struct {
	TS       int64                  `json:"ts"`
	Event    string                 `json:"event"`
	Category string                 `json:"category"`
	Conn     string                 `json:"conn_id_prefix,omitempty"`
	Source   string                 `json:"source,omitempty"`
	Fields   map[string]interface{} `json:"fields,omitempty"`
}

func (w *JSONLWriter) Write(ev Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	line := jsonlLine{
		TS:       ev.Timestamp.UnixMilli(),
		Event:    ev.EventType,
		Category: string(ev.Category),
		Conn:     ev.ConnIDPrefix,
		Source:   ev.Source,
		Fields:   ev.Fields,
	}
	return w.enc.Encode(line)
}

func (w *JSONLWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Close()
}

// ShortHash produces a short, non-reversible identifier suitable for
// ConnIDPrefix or for referencing a device_id/session_key in logs
// without exposing the value itself, per the §4 privacy rule.
// Deliberately NOT cryptographically reversible -- just enough entropy
// to correlate log lines belonging to the same session.
func ShortHash(secretOrID []byte) string {
	// FNV-1a, 32-bit -- fast, stdlib (hash/fnv), and explicitly NOT a
	// security primitive: this is only ever used to correlate log
	// lines, never as an authentication or lookup key.
	var h uint32 = 2166136261
	for _, b := range secretOrID {
		h ^= uint32(b)
		h *= 16777619
	}
	return fmt.Sprintf("%08x", h)
}
