package filter

import (
	"context"
	"testing"
	"time"

	"github.com/tkingovr/agent-guard/api"
)

func TestRateLimiter_PerToolLimit(t *testing.T) {
	f := NewRateLimitFilter(RateLimitConfig{
		PerTool: map[string]*RateLimit{
			"write_file": {Max: 3, Window: time.Minute},
		},
	})

	for i := 0; i < 3; i++ {
		fc := NewFilterContext(nil, api.DirectionInbound)
		fc.Method = "tools/call"
		fc.Tool = "write_file"

		if err := f.Process(context.Background(), fc); err != nil {
			t.Fatal(err)
		}
		if fc.Halted {
			t.Errorf("request %d should not be rate limited", i+1)
		}
	}

	// 4th request should be denied
	fc := NewFilterContext(nil, api.DirectionInbound)
	fc.Method = "tools/call"
	fc.Tool = "write_file"

	if err := f.Process(context.Background(), fc); err != nil {
		t.Fatal(err)
	}
	if !fc.Halted {
		t.Error("4th request should be rate limited")
	}
	if fc.Verdict != api.VerdictDeny {
		t.Errorf("expected deny, got %s", fc.Verdict)
	}
	if fc.MatchedRule != "rate_limit:write_file" {
		t.Errorf("expected rule rate_limit:write_file, got %s", fc.MatchedRule)
	}
}

func TestRateLimiter_GlobalLimit(t *testing.T) {
	f := NewRateLimitFilter(RateLimitConfig{
		Global: &RateLimit{Max: 2, Window: time.Minute},
	})

	// Two requests with different tools
	for _, tool := range []string{"read_file", "write_file"} {
		fc := NewFilterContext(nil, api.DirectionInbound)
		fc.Method = "tools/call"
		fc.Tool = tool

		if err := f.Process(context.Background(), fc); err != nil {
			t.Fatal(err)
		}
		if fc.Halted {
			t.Errorf("request for %s should not be rate limited", tool)
		}
	}

	// 3rd request should hit global limit
	fc := NewFilterContext(nil, api.DirectionInbound)
	fc.Method = "tools/call"
	fc.Tool = "another_tool"

	if err := f.Process(context.Background(), fc); err != nil {
		t.Fatal(err)
	}
	if !fc.Halted {
		t.Error("3rd request should hit global rate limit")
	}
	if fc.MatchedRule != "rate_limit:global" {
		t.Errorf("expected rule rate_limit:global, got %s", fc.MatchedRule)
	}
}

func TestRateLimiter_WindowExpiry(t *testing.T) {
	f := NewRateLimitFilter(RateLimitConfig{
		PerTool: map[string]*RateLimit{
			"test_tool": {Max: 1, Window: 50 * time.Millisecond},
		},
	})

	// First request allowed
	fc := NewFilterContext(nil, api.DirectionInbound)
	fc.Method = "tools/call"
	fc.Tool = "test_tool"
	f.Process(context.Background(), fc)
	if fc.Halted {
		t.Error("first request should be allowed")
	}

	// Second request denied
	fc = NewFilterContext(nil, api.DirectionInbound)
	fc.Method = "tools/call"
	fc.Tool = "test_tool"
	f.Process(context.Background(), fc)
	if !fc.Halted {
		t.Error("second request should be rate limited")
	}

	// Wait for window to expire
	time.Sleep(60 * time.Millisecond)

	// Third request should be allowed again
	fc = NewFilterContext(nil, api.DirectionInbound)
	fc.Method = "tools/call"
	fc.Tool = "test_tool"
	f.Process(context.Background(), fc)
	if fc.Halted {
		t.Error("request after window expiry should be allowed")
	}
}

func TestRateLimiter_SkipNonToolCalls(t *testing.T) {
	f := NewRateLimitFilter(RateLimitConfig{
		Global: &RateLimit{Max: 1, Window: time.Minute},
	})

	// Non-tool-call methods should not be rate limited
	fc := NewFilterContext(nil, api.DirectionInbound)
	fc.Method = "initialize"
	f.Process(context.Background(), fc)
	if fc.Halted {
		t.Error("initialize should not be rate limited")
	}
}

func TestRateLimiter_SkipOutbound(t *testing.T) {
	f := NewRateLimitFilter(RateLimitConfig{
		Global: &RateLimit{Max: 1, Window: time.Minute},
	})

	fc := NewFilterContext(nil, api.DirectionOutbound)
	fc.Method = "tools/call"
	fc.Tool = "test_tool"
	f.Process(context.Background(), fc)
	if fc.Halted {
		t.Error("outbound should not be rate limited")
	}
}

func TestRateLimiter_SkipHalted(t *testing.T) {
	f := NewRateLimitFilter(RateLimitConfig{
		Global: &RateLimit{Max: 1, Window: time.Minute},
	})

	fc := NewFilterContext(nil, api.DirectionInbound)
	fc.Method = "tools/call"
	fc.Tool = "test_tool"
	fc.Halted = true // Already denied by policy
	f.Process(context.Background(), fc)
	// Should not consume a rate limit token
	if fc.MatchedRule != "" {
		t.Error("halted requests should not be processed by rate limiter")
	}
}

func TestRateLimiter_Reset(t *testing.T) {
	f := NewRateLimitFilter(RateLimitConfig{
		PerTool: map[string]*RateLimit{
			"test_tool": {Max: 1, Window: time.Minute},
		},
	})

	// Use up the limit
	fc := NewFilterContext(nil, api.DirectionInbound)
	fc.Method = "tools/call"
	fc.Tool = "test_tool"
	f.Process(context.Background(), fc)

	// Reset
	f.Reset()

	// Should be allowed again
	fc = NewFilterContext(nil, api.DirectionInbound)
	fc.Method = "tools/call"
	fc.Tool = "test_tool"
	f.Process(context.Background(), fc)
	if fc.Halted {
		t.Error("request after reset should be allowed")
	}
}

func TestRateLimitConfigFromPolicy(t *testing.T) {
	cfg := RateLimitConfigFromPolicy(nil)
	if cfg != nil {
		t.Error("expected nil for nil settings")
	}
}
