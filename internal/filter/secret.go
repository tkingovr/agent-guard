package filter

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/tkingovr/agent-guard/api"
)

// SecretPattern defines a named regex pattern for detecting secrets.
type SecretPattern struct {
	Name  string
	Regex *regexp.Regexp
}

// DefaultSecretPatterns returns the built-in set of secret detection patterns.
func DefaultSecretPatterns() []SecretPattern {
	return []SecretPattern{
		{Name: "aws_access_key", Regex: regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`)},
		{Name: "aws_secret_key", Regex: regexp.MustCompile(`(?i)(?:aws)?_?(?:secret)?_?(?:access)?_?key['":\s]*[=:]\s*['"]?([A-Za-z0-9/+=]{40})`)},
		{Name: "github_token", Regex: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,255}`)},
		{Name: "github_pat_fine", Regex: regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,255}`)},
		{Name: "generic_api_key", Regex: regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|api_secret)['":\s]*[=:]\s*['"]?([A-Za-z0-9\-_]{20,60})['"]?`)},
		{Name: "generic_secret", Regex: regexp.MustCompile(`(?i)(?:secret|password|passwd|pwd|token|auth_token|access_token|bearer)['":\s]*[=:]\s*['"]?([A-Za-z0-9\-_!@#$%^&*]{8,100})['"]?`)},
		{Name: "private_key", Regex: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)},
		{Name: "slack_token", Regex: regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`)},
		{Name: "stripe_key", Regex: regexp.MustCompile(`(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,100}`)},
		{Name: "google_api_key", Regex: regexp.MustCompile(`AIza[A-Za-z0-9\-_]{35}`)},
		{Name: "jwt_token", Regex: regexp.MustCompile(`eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+`)},
		{Name: "ssh_private_key_path", Regex: regexp.MustCompile(`(?i)(?:\.ssh/id_(?:rsa|ed25519|ecdsa|dsa)|\.pem)`)},
	}
}

// SecretScannerFilter scans arguments for secrets using regex patterns and entropy analysis.
type SecretScannerFilter struct {
	patterns         []SecretPattern
	entropyThreshold float64
	minTokenLength   int
}

// SecretScannerOption configures the SecretScannerFilter.
type SecretScannerOption func(*SecretScannerFilter)

// WithPatterns sets custom secret patterns (replaces defaults).
func WithPatterns(patterns []SecretPattern) SecretScannerOption {
	return func(f *SecretScannerFilter) {
		f.patterns = patterns
	}
}

// WithEntropyThreshold sets the Shannon entropy threshold for high-entropy string detection.
// Default is 4.5 (a random 32-char hex string has ~4.0 entropy).
func WithEntropyThreshold(threshold float64) SecretScannerOption {
	return func(f *SecretScannerFilter) {
		f.entropyThreshold = threshold
	}
}

// NewSecretScannerFilter creates a new secret scanner filter.
func NewSecretScannerFilter(opts ...SecretScannerOption) *SecretScannerFilter {
	f := &SecretScannerFilter{
		patterns:         DefaultSecretPatterns(),
		entropyThreshold: 4.5,
		minTokenLength:   20,
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

func (f *SecretScannerFilter) Name() string { return "secret_scanner" }

func (f *SecretScannerFilter) Process(_ context.Context, fc *FilterContext) error {
	// Only scan inbound requests
	if fc.Direction != api.DirectionInbound {
		return nil
	}

	// Skip if already denied
	if fc.Halted {
		return nil
	}

	// Scan the raw message for secret patterns
	text := string(fc.Raw)

	// Check regex patterns
	for _, p := range f.patterns {
		if p.Regex.MatchString(text) {
			fc.Verdict = api.VerdictDeny
			fc.MatchedRule = "secret_scanner:" + p.Name
			fc.VerdictMessage = fmt.Sprintf("potential secret detected: %s pattern matched", p.Name)
			fc.Halted = true
			return nil
		}
	}

	// Check high-entropy strings in arguments
	if fc.Arguments != nil {
		if token, found := f.findHighEntropyToken(string(fc.Arguments)); found {
			fc.Verdict = api.VerdictDeny
			fc.MatchedRule = "secret_scanner:high_entropy"
			fc.VerdictMessage = fmt.Sprintf("potential secret detected: high-entropy string (%.1f bits) starting with %q",
				shannonEntropy(token), truncateStr(token, 8))
			fc.Halted = true
			return nil
		}
	}

	return nil
}

// findHighEntropyToken splits text into tokens and checks each for high entropy.
func (f *SecretScannerFilter) findHighEntropyToken(text string) (string, bool) {
	// Extract string values from JSON-like text
	tokens := extractStringTokens(text)
	for _, token := range tokens {
		if len(token) >= f.minTokenLength && shannonEntropy(token) >= f.entropyThreshold {
			return token, true
		}
	}
	return "", false
}

// extractStringTokens extracts quoted string values from text.
func extractStringTokens(text string) []string {
	var tokens []string
	// Simple extraction: find quoted strings
	inQuote := false
	var current strings.Builder
	for i := 0; i < len(text); i++ {
		if text[i] == '"' {
			if inQuote {
				t := current.String()
				if t != "" {
					tokens = append(tokens, t)
				}
				current.Reset()
			}
			inQuote = !inQuote
			continue
		}
		if text[i] == '\\' && i+1 < len(text) {
			i++ // skip escaped char
			if inQuote {
				current.WriteByte(text[i])
			}
			continue
		}
		if inQuote {
			current.WriteByte(text[i])
		}
	}
	return tokens
}

// shannonEntropy calculates Shannon entropy of a string in bits per character.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}

	length := float64(len([]rune(s)))
	entropy := 0.0
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func truncateStr(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
