// Package sqlitewriter implements observability.EventWriter backed by
// SQLite (modernc.org/sqlite -- pure Go, no cgo, so it still
// cross-compiles cleanly for Android via gomobile). Isolated into its
// own Go module because this offline build environment could not fetch
// the dependency -- run `go mod tidy` here (with network) before
// building.
//
// Schema matches the design fixed in PROTOCOL.md §4: one `events` table
// with a JSON blob column for event-specific fields, indexed by
// (event_type, ts) and by conn_id_prefix.
package sqlitewriter

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"turboflare-transport/observability"
)

const schema = `
CREATE TABLE IF NOT EXISTS events (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	ts            INTEGER NOT NULL,
	event_type    TEXT NOT NULL,
	category      TEXT NOT NULL,
	conn_id_prefix TEXT,
	source        TEXT,
	fields_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events(event_type, ts);
CREATE INDEX IF NOT EXISTS idx_events_conn ON events(conn_id_prefix);
`

type Writer struct {
	mu sync.Mutex
	db *sql.DB
}

// New opens (creating if necessary) a SQLite database at path and
// ensures the events table/indexes exist.
func New(path string) (*Writer, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("sqlitewriter: open: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlitewriter: schema init: %w", err)
	}
	return &Writer{db: db}, nil
}

func (w *Writer) Write(ev observability.Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	fieldsJSON, err := json.Marshal(ev.Fields)
	if err != nil {
		return fmt.Errorf("sqlitewriter: marshal fields: %w", err)
	}

	_, err = w.db.Exec(
		`INSERT INTO events (ts, event_type, category, conn_id_prefix, source, fields_json)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		ev.Timestamp.UnixMilli(), ev.EventType, string(ev.Category), ev.ConnIDPrefix, ev.Source, string(fieldsJSON),
	)
	return err
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.db.Close()
}

// Rotate deletes events older than maxAge, per the §4 rotation-by-age
// option. Call this periodically (e.g. once per app start) rather than
// on every write.
func (w *Writer) Rotate(maxAge time.Duration) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	cutoff := time.Now().Add(-maxAge).UnixMilli()
	_, err := w.db.Exec(`DELETE FROM events WHERE ts < ?`, cutoff)
	return err
}

var _ observability.EventWriter = (*Writer)(nil)
