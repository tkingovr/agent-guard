package filter

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/tkingovr/agent-guard/api"
)

// RateLimitConfig defines rate limiting rules.
type RateLimitConfig struct {
	// Global is the global rate limit (requests per window across all tools).
	Global *RateLimit

	// PerTool maps tool names to per-tool rate limits.
	PerTool map[string]*RateLimit
}

// RateLimit defines a single rate limit: max requests per time window.
type RateLimit struct {
	Max    int
	Window time.Duration
}

// slidingWindow tracks request timestamps for rate limiting.
type slidingWindow struct {
	mu         sync.Mutex
	timestamps []time.Time
}

// RateLimitFilter enforces per-tool and global rate limits using a sliding window.
type RateLimitFilter struct {
	config  RateLimitConfig
	mu      sync.RWMutex
	windows map[string]*slidingWindow // key: tool name or "_global"
}

// NewRateLimitFilter creates a new rate limit filter.
func NewRateLimitFilter(config RateLimitConfig) *RateLimitFilter {
	return &RateLimitFilter{
		config:  config,
		windows: make(map[string]*slidingWindow),
	}
}

func (f *RateLimitFilter) Name() string { return "rate_limit" }

func (f *RateLimitFilter) Process(_ context.Context, fc *FilterContext) error {
	// Only rate limit inbound tool calls
	if fc.Direction != api.DirectionInbound {
		return nil
	}
	if fc.Halted {
		return nil
	}
	if fc.Method != "tools/call" {
		return nil
	}

	now := time.Now()

	// Check per-tool limit
	if fc.Tool != "" {
		if limit, ok := f.config.PerTool[fc.Tool]; ok {
			if !f.allow(fc.Tool, limit, now) {
				fc.Verdict = api.VerdictDeny
				fc.MatchedRule = "rate_limit:" + fc.Tool
				fc.VerdictMessage = fmt.Sprintf("rate limit exceeded for tool %q: max %d per %s",
					fc.Tool, limit.Max, limit.Window)
				fc.Halted = true
				return nil
			}
		}
	}

	// Check global limit
	if f.config.Global != nil {
		if !f.allow("_global", f.config.Global, now) {
			fc.Verdict = api.VerdictDeny
			fc.MatchedRule = "rate_limit:global"
			fc.VerdictMessage = fmt.Sprintf("global rate limit exceeded: max %d per %s",
				f.config.Global.Max, f.config.Global.Window)
			fc.Halted = true
			return nil
		}
	}

	return nil
}

// allow checks if a request is allowed under the given rate limit.
func (f *RateLimitFilter) allow(key string, limit *RateLimit, now time.Time) bool {
	f.mu.Lock()
	w, ok := f.windows[key]
	if !ok {
		w = &slidingWindow{}
		f.windows[key] = w
	}
	f.mu.Unlock()

	w.mu.Lock()
	defer w.mu.Unlock()

	// Remove expired timestamps
	cutoff := now.Add(-limit.Window)
	valid := 0
	for _, ts := range w.timestamps {
		if ts.After(cutoff) {
			w.timestamps[valid] = ts
			valid++
		}
	}
	w.timestamps = w.timestamps[:valid]

	// Check limit
	if len(w.timestamps) >= limit.Max {
		return false
	}

	// Record this request
	w.timestamps = append(w.timestamps, now)
	return true
}

// Reset clears all rate limit windows (useful for testing).
func (f *RateLimitFilter) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.windows = make(map[string]*slidingWindow)
}
