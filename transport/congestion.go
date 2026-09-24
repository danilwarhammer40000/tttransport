package transport

import (
	"sync"
	"time"
)

// CongestionController implements the "impulsive burst" model fixed in
// PROTOCOL.md §1-2: NOT an AIMD throughput-maximizer. The explicit goal
// is staying visibly below the CDN's technical ceiling (found during the
// original research) rather than probing for it, and mimicking a real
// browser's burst/idle request pattern rather than a steady drip.
type CongestionController struct {
	mu sync.Mutex

	// Window (parallel in-flight HTTP transactions).
	WBaseline    uint32 // idle-state window, default 2
	WBurstTarget uint32 // ceiling to jump to when a burst starts, default 8
	WBurstAbsMax uint32 // hard ceiling never exceeded regardless of penalty state, default 10

	currentWindow uint32
	inBurst       bool
	burstStarted  time.Time
	burstTimeout  time.Duration // default ~1.5s, per design (~1-2s)

	burstCeilingPenalty float64 // multiplier in (0,1], applied to WBurstTarget after an error
	cleanBurstStreak    int     // consecutive clean (error-free) bursts, used to recover penalty

	// Block size (bytes per HTTP transaction body).
	BlockMin        uint32 // 4 KiB hard floor
	BlockMax        uint32 // 64 KiB hard ceiling (CDN's tested technical limit)
	BlockSoftTarget uint32 // ~16 KiB, the deliberately conservative working point
	BlockSoftMax    uint32 // ~24 KiB, soft ceiling we don't grow past by default

	currentBlockSize uint32
	cleanTxStreak    int // consecutive clean transactions, gates slow block growth

	// RTT tracking (Jacobson-style EWMA).
	rttAvg time.Duration
	rttVar time.Duration
	rttSet bool

	MinTimeout time.Duration
	MaxTimeout time.Duration
}

const (
	DefaultWBaseline    = 2
	DefaultWBurstTarget = 8
	DefaultWBurstAbsMax = 10
	DefaultBurstTimeout = 1500 * time.Millisecond

	DefaultBlockMin        = 4 * 1024
	DefaultBlockMax        = 64 * 1024
	DefaultBlockSoftTarget = 16 * 1024
	DefaultBlockSoftMax    = 24 * 1024

	DefaultMinTimeout = 500 * time.Millisecond
	DefaultMaxTimeout = 10 * time.Second

	// After an error inside a burst, the next burst's ceiling is
	// multiplied by this factor; recovers by CeilingRecoveryStep per
	// clean burst, back up to 1.0.
	CeilingPenaltyFactor = 0.8
	CeilingRecoveryStep  = 0.05
	CleanBurstsToRecover = 4 // roughly how many clean bursts to fully recover from one penalty

	// How many consecutive clean transactions before block size is
	// allowed to grow at all.
	CleanTxStreakForGrowth = 25
	BlockGrowthFactor      = 1.1
	BlockShrinkStep        = 4 * 1024
)

func NewCongestionController() *CongestionController {
	c := &CongestionController{
		WBaseline:           DefaultWBaseline,
		WBurstTarget:        DefaultWBurstTarget,
		WBurstAbsMax:        DefaultWBurstAbsMax,
		burstTimeout:        DefaultBurstTimeout,
		burstCeilingPenalty: 1.0,

		BlockMin:        DefaultBlockMin,
		BlockMax:        DefaultBlockMax,
		BlockSoftTarget: DefaultBlockSoftTarget,
		BlockSoftMax:    DefaultBlockSoftMax,

		MinTimeout: DefaultMinTimeout,
		MaxTimeout: DefaultMaxTimeout,
	}
	c.currentWindow = c.WBaseline
	c.currentBlockSize = c.BlockSoftTarget
	return c
}

// OnQueueNonEmpty signals that data has accumulated waiting to be sent.
// Per the fixed design this triggers an immediate jump to burst window,
// not a gradual ramp.
func (c *CongestionController) OnQueueNonEmpty() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inBurst {
		return
	}
	c.inBurst = true
	c.burstStarted = time.Now()
	ceiling := float64(c.WBurstTarget) * c.burstCeilingPenalty
	w := uint32(ceiling)
	if w < c.WBaseline {
		w = c.WBaseline
	}
	if w > c.WBurstAbsMax {
		w = c.WBurstAbsMax
	}
	c.currentWindow = w
}

// OnQueueEmpty signals the send queue has drained -- burst ends cleanly,
// window drops back to baseline (also a jump, not a fade).
func (c *CongestionController) OnQueueEmpty() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.inBurst {
		return
	}
	c.endBurstLocked(true)
}

// CheckBurstTimeout should be polled periodically (e.g. by the session
// event loop); ends the burst if it has run longer than burstTimeout
// even though the queue never fully emptied.
func (c *CongestionController) CheckBurstTimeout() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.inBurst {
		return
	}
	if time.Since(c.burstStarted) >= c.burstTimeout {
		c.endBurstLocked(true)
	}
}

// endBurstLocked must be called with mu held.
func (c *CongestionController) endBurstLocked(clean bool) {
	c.inBurst = false
	c.currentWindow = c.WBaseline
	if clean {
		c.cleanBurstStreak++
		if c.cleanBurstStreak >= CleanBurstsToRecover && c.burstCeilingPenalty < 1.0 {
			c.burstCeilingPenalty += CeilingRecoveryStep
			if c.burstCeilingPenalty > 1.0 {
				c.burstCeilingPenalty = 1.0
			}
			c.cleanBurstStreak = 0
		}
	}
}

// OnError must be called on ANY transaction failure: timeout, 5xx, or
// incomplete response. Per the fixed design, window and block size react
// differently -- see OnTimeoutOr5xx / OnIncompleteResponse below, which
// both call this shared burst-abort logic first.
func (c *CongestionController) onErrorLocked() {
	if c.inBurst {
		c.endBurstLocked(false)
		c.burstCeilingPenalty *= CeilingPenaltyFactor
		if c.burstCeilingPenalty < 0.2 {
			c.burstCeilingPenalty = 0.2 // never let a burst shrink to near-nothing permanently
		}
		c.cleanBurstStreak = 0
	}
	c.cleanTxStreak = 0
}

// OnTimeoutOrServerError reacts to a timeout or HTTP 5xx: linear window
// decrease (never halving -- an abrupt drop is itself an anomalous
// pattern relative to the "look like a browser" goal), plus the shared
// burst-abort behavior.
func (c *CongestionController) OnTimeoutOrServerError() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onErrorLocked()
	if c.currentWindow > c.WBaseline {
		c.currentWindow--
	}
}

// OnIncompleteResponse reacts to a CDN-truncated response body: per the
// fixed design this reduces BLOCK SIZE, not window, since the original
// research (§11/§13) tied incomplete responses to body size, not
// concurrency.
func (c *CongestionController) OnIncompleteResponse() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onErrorLocked()
	if c.currentBlockSize > c.BlockMin+BlockShrinkStep {
		c.currentBlockSize -= BlockShrinkStep
	} else {
		c.currentBlockSize = c.BlockMin
	}
}

// OnSuccess records a successful transaction's RTT and, after a long
// enough clean streak, allows a small, rare block-size increase --
// deliberately capped at BlockSoftMax, well below the CDN's tested
// technical ceiling.
func (c *CongestionController) OnSuccess(rtt time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.updateRTTLocked(rtt)

	c.cleanTxStreak++
	if c.cleanTxStreak >= CleanTxStreakForGrowth {
		c.cleanTxStreak = 0
		grown := uint32(float64(c.currentBlockSize) * BlockGrowthFactor)
		if grown > c.BlockSoftMax {
			grown = c.BlockSoftMax
		}
		c.currentBlockSize = grown
	}
}

func (c *CongestionController) updateRTTLocked(sample time.Duration) {
	if !c.rttSet {
		c.rttAvg = sample
		c.rttVar = sample / 2
		c.rttSet = true
		return
	}
	diff := sample - c.rttAvg
	if diff < 0 {
		diff = -diff
	}
	// EWMA per Jacobson's algorithm: alpha = 1/8 for avg, 1/4 for var.
	c.rttAvg = c.rttAvg + (sample-c.rttAvg)/8
	c.rttVar = c.rttVar + (diff-c.rttVar)/4
}

// Timeout returns the current retransmit timeout: RTT_avg + 4*RTT_var,
// clamped to [MinTimeout, MaxTimeout].
func (c *CongestionController) Timeout() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.rttSet {
		return c.MinTimeout
	}
	t := c.rttAvg + 4*c.rttVar
	if t < c.MinTimeout {
		return c.MinTimeout
	}
	if t > c.MaxTimeout {
		return c.MaxTimeout
	}
	return t
}

func (c *CongestionController) CurrentWindow() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.currentWindow
}

func (c *CongestionController) CurrentBlockSize() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.currentBlockSize
}

// InBurst reports whether the controller currently considers itself in
// a burst period -- useful for the traffic-shaping layer to mirror the
// same state (per the fixed decision that congestion control and
// traffic shaping share one burst/idle model).
func (c *CongestionController) InBurst() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inBurst
}
