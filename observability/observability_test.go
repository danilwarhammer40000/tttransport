package observability

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

func TestConfig_CategoryToggleRespected(t *testing.T) {
	cfg := DefaultDevConfig()
	cfg.Categories[CatRawHeaders] = false

	if cfg.enabled(CatRawHeaders) {
		t.Fatal("CatRawHeaders should be disabled after explicit toggle-off")
	}
	if !cfg.enabled(CatTxSend) {
		t.Fatal("other categories should remain enabled")
	}
}

func TestConfig_SilentExceptErrors(t *testing.T) {
	cfg := DefaultDevConfig()
	cfg.Verbosity = VerbositySilentExceptErrors

	if cfg.enabled(CatTxSend) {
		t.Fatal("SILENT_EXCEPT_ERRORS should suppress non-error categories")
	}
	if !cfg.enabled(CatTxError) {
		t.Fatal("SILENT_EXCEPT_ERRORS must still allow tx_error")
	}
}

func TestJSONLWriter_WritesValidLines(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "turboflare-log-*.jsonl")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	path := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(path)

	w, err := NewJSONLWriter(path)
	if err != nil {
		t.Fatalf("NewJSONLWriter: %v", err)
	}
	logger := NewLogger(DefaultDevConfig(), w)

	logger.Log(CatTxSend, "tx_send", "abcd1234", "traffic", map[string]interface{}{
		"seq": 42, "block_size": 16384,
	})
	logger.Log(CatRawHeaders, "raw_headers", "abcd1234", "traffic", map[string]interface{}{
		"headers": "should be logged, category is on by default",
	})

	if err := logger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("reopen log file: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var lines []jsonlLine
	for scanner.Scan() {
		var l jsonlLine
		if err := json.Unmarshal(scanner.Bytes(), &l); err != nil {
			t.Fatalf("invalid JSON line: %v (%s)", err, scanner.Text())
		}
		lines = append(lines, l)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 log lines, got %d", len(lines))
	}
	if lines[0].Event != "tx_send" || lines[0].Conn != "abcd1234" {
		t.Fatalf("unexpected first line: %+v", lines[0])
	}
}

func TestJSONLWriter_DisabledCategoryNotWritten(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "turboflare-log-*.jsonl")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	path := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(path)

	w, err := NewJSONLWriter(path)
	if err != nil {
		t.Fatalf("NewJSONLWriter: %v", err)
	}
	cfg := DefaultDevConfig()
	cfg.Categories[CatTxSend] = false
	logger := NewLogger(cfg, w)

	logger.Log(CatTxSend, "tx_send", "", "traffic", nil)
	logger.Close()

	data, _ := os.ReadFile(path)
	if len(data) != 0 {
		t.Fatalf("expected no bytes written for a disabled category, got %q", data)
	}
}

func TestShortHash_Deterministic(t *testing.T) {
	a := ShortHash([]byte("device-id-bytes"))
	b := ShortHash([]byte("device-id-bytes"))
	c := ShortHash([]byte("different-bytes"))
	if a != b {
		t.Fatal("ShortHash must be deterministic for the same input")
	}
	if a == c {
		t.Fatal("ShortHash should differ for different input (collision in this tiny test would be a red flag)")
	}
}

func TestTestMode_SummaryReflectsProbeResults(t *testing.T) {
	tm := NewTestMode(nil)

	tm.Register("always_pass", func() CheckResult {
		return CheckResult{Status: StatusPass, Detail: "ok"}
	})
	tm.Register("always_fail", func() CheckResult {
		return CheckResult{Status: StatusFail, Detail: "broken"}
	})

	summary := tm.Run()
	if len(summary.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(summary.Results))
	}
	if summary.Results[0].Status != StatusPass || summary.Results[1].Status != StatusFail {
		t.Fatalf("unexpected statuses: %+v", summary.Results)
	}
}

func TestNewCDNBodyLimitProbe_ReportsFirstFailure(t *testing.T) {
	push := func(size int) (bool, error) {
		return size < 48*1024, nil // simulate incomplete responses starting at 48KiB
	}
	probe := NewCDNBodyLimitProbe(push, []int{16 * 1024, 32 * 1024, 48 * 1024, 64 * 1024})
	res := probe()
	if res.Status != StatusWarn {
		t.Fatalf("expected WARN status, got %s", res.Status)
	}
	if res.Data["first_failure_bytes"] != 48*1024 {
		t.Fatalf("expected first_failure_bytes=%d, got %v", 48*1024, res.Data["first_failure_bytes"])
	}
}

func TestNewRTTBaselineProbe_ComputesAverage(t *testing.T) {
	calls := 0
	rtt := func() (time.Duration, error) {
		calls++
		return time.Duration(calls) * 10 * time.Millisecond, nil
	}
	probe := NewRTTBaselineProbe(rtt, 3)
	res := probe()
	if res.Status != StatusInfo {
		t.Fatalf("expected INFO status, got %s", res.Status)
	}
	if res.Data["samples"] != 3 {
		t.Fatalf("expected 3 samples, got %v", res.Data["samples"])
	}
}

func TestNewReconnectProbe_FailsOnError(t *testing.T) {
	probe := NewReconnectProbe(func() (bool, time.Duration, error) {
		return false, 0, errors.New("simulated network failure")
	})
	res := probe()
	if res.Status != StatusFail {
		t.Fatalf("expected FAIL status, got %s", res.Status)
	}
}
