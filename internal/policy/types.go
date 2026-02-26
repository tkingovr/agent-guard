package policy

import (
	"encoding/json"

	"github.com/tkingovr/agent-guard/api"
)

// PolicyFile represents the top-level YAML policy configuration.
type PolicyFile struct {
	Version  int      `yaml:"version" json:"version"`
	Settings Settings `yaml:"settings" json:"settings"`
	Rules    []Rule   `yaml:"rules" json:"rules"`
}

// Settings contains global policy settings.
type Settings struct {
	DefaultAction   api.Verdict      `yaml:"default_action" json:"default_action"`
	LogDir          string           `yaml:"log_dir" json:"log_dir"`
	DashboardAddr   string           `yaml:"dashboard_addr" json:"dashboard_addr"`
	ApprovalTimeout string           `yaml:"approval_timeout" json:"approval_timeout"`
	OPAPolicy       string           `yaml:"opa_policy,omitempty" json:"opa_policy,omitempty"`
	SecretScanner   *SecretSettings  `yaml:"secret_scanner,omitempty" json:"secret_scanner,omitempty"`
	RateLimit       *RateLimitSettings `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"`
}

// SecretSettings configures the secret scanner filter.
type SecretSettings struct {
	Enabled          bool    `yaml:"enabled" json:"enabled"`
	EntropyThreshold float64 `yaml:"entropy_threshold,omitempty" json:"entropy_threshold,omitempty"`
}

// RateLimitSettings configures rate limiting.
type RateLimitSettings struct {
	Global  *RateLimitRule            `yaml:"global,omitempty" json:"global,omitempty"`
	PerTool map[string]*RateLimitRule `yaml:"per_tool,omitempty" json:"per_tool,omitempty"`
}

// RateLimitRule defines a rate limit: max requests per time window.
type RateLimitRule struct {
	Max    int    `yaml:"max" json:"max"`
	Window string `yaml:"window" json:"window"`
}

// Rule represents a single policy rule.
type Rule struct {
	Name    string    `yaml:"name" json:"name"`
	Match   RuleMatch `yaml:"match" json:"match"`
	Action  string    `yaml:"action" json:"action"`
	Message string    `yaml:"message,omitempty" json:"message,omitempty"`
}

// RuleMatch specifies conditions for matching a request.
type RuleMatch struct {
	Method    string                   `yaml:"method,omitempty" json:"method,omitempty"`
	Tool      string                   `yaml:"tool,omitempty" json:"tool,omitempty"`
	Arguments map[string]ArgumentMatch `yaml:"arguments,omitempty" json:"arguments,omitempty"`
}

// ArgumentMatch specifies a matching condition for a single argument.
type ArgumentMatch struct {
	Exact string `yaml:"exact,omitempty" json:"exact,omitempty"`
	Regex string `yaml:"regex,omitempty" json:"regex,omitempty"`
}

// EvalInput is the input to a policy engine evaluation.
type EvalInput struct {
	Method    string          `json:"method"`
	Tool      string          `json:"tool,omitempty"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// EvalResult is the output of a policy engine evaluation.
type EvalResult struct {
	Verdict api.Verdict `json:"verdict"`
	Rule    string      `json:"rule,omitempty"`
	Message string      `json:"message,omitempty"`
}
