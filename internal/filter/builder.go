package filter

import (
	"log/slog"
	"time"

	"github.com/tkingovr/agent-guard/internal/audit"
	"github.com/tkingovr/agent-guard/internal/policy"
)

// ChainConfig holds the configuration for building filter chains.
type ChainConfig struct {
	Engine           policy.Engine
	AuditStore       audit.Store
	Logger           *slog.Logger
	SecretScanner    bool
	EntropyThreshold float64
	RateLimit        *RateLimitConfig
}

// BuildInboundChain constructs the inbound (client→server) filter chain.
func BuildInboundChain(cfg ChainConfig) *Chain {
	filters := []Filter{
		NewParseFilter(),
		NewPolicyFilter(cfg.Engine),
	}

	// Add secret scanner after policy (so policy denials take precedence)
	if cfg.SecretScanner {
		opts := []SecretScannerOption{}
		if cfg.EntropyThreshold > 0 {
			opts = append(opts, WithEntropyThreshold(cfg.EntropyThreshold))
		}
		filters = append(filters, NewSecretScannerFilter(opts...))
	}

	// Add rate limiter
	if cfg.RateLimit != nil {
		filters = append(filters, NewRateLimitFilter(*cfg.RateLimit))
	}

	// Audit is always last
	filters = append(filters, NewAuditFilter(cfg.AuditStore))

	return NewChain(cfg.Logger, filters...)
}

// BuildOutboundChain constructs the outbound (server→client) filter chain.
func BuildOutboundChain(cfg ChainConfig) *Chain {
	return NewChain(cfg.Logger,
		NewOutboundParseFilter(),
		NewAuditFilter(cfg.AuditStore),
	)
}

// RateLimitConfigFromPolicy converts policy rate limit settings to filter config.
func RateLimitConfigFromPolicy(settings *policy.RateLimitSettings) *RateLimitConfig {
	if settings == nil {
		return nil
	}

	cfg := &RateLimitConfig{
		PerTool: make(map[string]*RateLimit),
	}

	if settings.Global != nil {
		d, err := time.ParseDuration(settings.Global.Window)
		if err == nil {
			cfg.Global = &RateLimit{Max: settings.Global.Max, Window: d}
		}
	}

	for tool, rule := range settings.PerTool {
		d, err := time.ParseDuration(rule.Window)
		if err == nil {
			cfg.PerTool[tool] = &RateLimit{Max: rule.Max, Window: d}
		}
	}

	return cfg
}
