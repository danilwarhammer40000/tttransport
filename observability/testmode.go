package observability

import (
	"fmt"
	"time"
)

// CheckStatus is the verdict for one diagnostic probe.
type CheckStatus string

const (
	StatusPass CheckStatus = "PASS"
	StatusWarn CheckStatus = "WARN"
	StatusFail CheckStatus = "FAIL"
	StatusInfo CheckStatus = "INFO" // informational, not pass/fail (e.g. RTT baseline)
)

type CheckResult struct {
	Check  string      `json:"check"`
	Status CheckStatus `json:"status"`
	Detail string      `json:"detail,omitempty"`
	Data   map[string]interface{} `json:"data,omitempty"`
}

type TestRunSummary struct {
	StartedAt  time.Time     `json:"-"`
	DurationMs int64         `json:"duration_ms"`
	Results    []CheckResult `json:"results"`
}

// Probe is one diagnostic check function per PROTOCOL.md §4. Each probe
// is injected rather than hard-wired here, so TestMode has no direct
// dependency on the client/, fingerprint/, or utlsclient packages --
// wire the real ones up at the call site (see Example below).
type Probe func() CheckResult

// TestMode orchestrates a set of probes and produces a structured
// summary, logged with Source: "test_mode" (tagged separately from
// normal traffic per the fixed design).
type TestMode struct {
	Logger *Logger
	Probes []NamedProbe
}

type NamedProbe struct {
	Name  string
	Probe Probe
}

func NewTestMode(logger *Logger) *TestMode {
	return &TestMode{Logger: logger}
}

func (tm *TestMode) Register(name string, p Probe) {
	tm.Probes = append(tm.Probes, NamedProbe{Name: name, Probe: p})
}

// Run executes all registered probes in order and returns the summary.
// Also logs each individual result (CatTestMode) and a final
// "test_run_summary" event.
func (tm *TestMode) Run() TestRunSummary {
	start := time.Now()
	summary := TestRunSummary{StartedAt: start}

	for _, np := range tm.Probes {
		res := np.Probe()
		res.Check = np.Name
		summary.Results = append(summary.Results, res)

		if tm.Logger != nil {
			tm.Logger.Log(CatTestMode, "test_check_result", "", "test_mode", map[string]interface{}{
				"check":  res.Check,
				"status": string(res.Status),
				"detail": res.Detail,
			})
		}
	}

	summary.DurationMs = time.Since(start).Milliseconds()

	if tm.Logger != nil {
		fieldResults := make([]map[string]interface{}, 0, len(summary.Results))
		for _, r := range summary.Results {
			fieldResults = append(fieldResults, map[string]interface{}{
				"check": r.Check, "status": string(r.Status), "detail": r.Detail,
			})
		}
		tm.Logger.Log(CatTestMode, "test_run_summary", "", "test_mode", map[string]interface{}{
			"duration_ms": summary.DurationMs,
			"results":     fieldResults,
		})
	}

	return summary
}

// ---------------------------------------------------------------------
// Reference probe implementations for the checks fixed in §4. These are
// written against small functional interfaces (not concrete client/
// transport types) so this package stays dependency-light; wire real
// implementations from your main() / test harness.
// ---------------------------------------------------------------------

// PushFunc sends n bytes of payload and reports whether the full
// response/ack was received intact (used for the CDN body-limit probe).
type PushFunc func(sizeBytes int) (ok bool, err error)

// NewCDNBodyLimitProbe replicates the original research's incremental
// body-size test (§10-11 of the first report): 16K/32K/64K, recording
// the size at which incomplete responses start appearing.
func NewCDNBodyLimitProbe(push PushFunc, sizesBytes []int) Probe {
	return func() CheckResult {
		var firstFailure int = -1
		var attempts, failures int
		for _, size := range sizesBytes {
			attempts++
			ok, err := push(size)
			if err != nil || !ok {
				failures++
				if firstFailure == -1 {
					firstFailure = size
				}
			}
		}
		if firstFailure == -1 {
			return CheckResult{Status: StatusPass, Detail: "no incomplete responses across tested sizes"}
		}
		rate := float64(failures) / float64(attempts) * 100
		return CheckResult{
			Status: StatusWarn,
			Detail: fmt.Sprintf("incomplete responses starting at %d bytes (%.0f%% failure rate across tested sizes)", firstFailure, rate),
			Data:   map[string]interface{}{"first_failure_bytes": firstFailure, "failure_rate_pct": rate},
		}
	}
}

// RTTFunc performs one round-trip and returns its duration.
type RTTFunc func() (time.Duration, error)

// NewRTTBaselineProbe runs n idle round-trips and reports avg/min/max --
// purely informational (STATUS_INFO), per §4.
func NewRTTBaselineProbe(rtt RTTFunc, samples int) Probe {
	return func() CheckResult {
		var sum, min, max time.Duration
		count := 0
		for i := 0; i < samples; i++ {
			d, err := rtt()
			if err != nil {
				continue
			}
			if count == 0 || d < min {
				min = d
			}
			if d > max {
				max = d
			}
			sum += d
			count++
		}
		if count == 0 {
			return CheckResult{Status: StatusFail, Detail: "no successful RTT samples"}
		}
		avg := sum / time.Duration(count)
		return CheckResult{
			Status: StatusInfo,
			Detail: fmt.Sprintf("rtt avg=%s min=%s max=%s over %d samples", avg, min, max, count),
			Data: map[string]interface{}{
				"rtt_avg_ms": avg.Milliseconds(),
				"rtt_min_ms": min.Milliseconds(),
				"rtt_max_ms": max.Milliseconds(),
				"samples":    count,
			},
		}
	}
}

// ReconnectFunc simulates a network-interface change and reports
// whether the reconnect completed (grace closed via confirmation) and
// how long it took.
type ReconnectFunc func() (confirmed bool, elapsed time.Duration, err error)

func NewReconnectProbe(reconnect ReconnectFunc) Probe {
	return func() CheckResult {
		confirmed, elapsed, err := reconnect()
		if err != nil {
			return CheckResult{Status: StatusFail, Detail: fmt.Sprintf("reconnect error: %v", err)}
		}
		if !confirmed {
			return CheckResult{Status: StatusFail, Detail: "grace period expired without key confirmation"}
		}
		return CheckResult{
			Status: StatusPass,
			Detail: fmt.Sprintf("reconnect handled correctly, grace closed in %s", elapsed),
			Data:   map[string]interface{}{"grace_closed_ms": elapsed.Milliseconds()},
		}
	}
}

// FingerprintCheckFunc reports whether the actually-applied TLS/HTTP2
// fingerprint matches the intended profile. Wire this to utlsclient +
// a packet-capture-based verifier once fingerprint/utlsclient is built
// (see its README) -- this package has no direct dependency on it.
type FingerprintCheckFunc func() (matches bool, mismatchDetail string, err error)

func NewFingerprintProbe(name string, check FingerprintCheckFunc) Probe {
	return func() CheckResult {
		matches, detail, err := check()
		if err != nil {
			return CheckResult{Status: StatusFail, Detail: fmt.Sprintf("%s check error: %v", name, err)}
		}
		if !matches {
			return CheckResult{Status: StatusFail, Detail: fmt.Sprintf("MISMATCH: %s", detail)}
		}
		return CheckResult{Status: StatusPass, Detail: fmt.Sprintf("%s applied as expected", name)}
	}
}
