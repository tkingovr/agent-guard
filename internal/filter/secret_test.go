package filter

import (
	"context"
	"testing"

	"github.com/tkingovr/agent-guard/api"
)

func TestSecretScanner_DetectAWSKey(t *testing.T) {
	f := NewSecretScannerFilter()
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_command","arguments":{"command":"export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}}}`)
	fc := NewFilterContext(raw, api.DirectionInbound)
	fc.Method = "tools/call"

	if err := f.Process(context.Background(), fc); err != nil {
		t.Fatal(err)
	}
	if fc.Verdict != api.VerdictDeny {
		t.Errorf("expected deny for AWS key, got %s", fc.Verdict)
	}
	if fc.MatchedRule != "secret_scanner:aws_access_key" {
		t.Errorf("expected rule secret_scanner:aws_access_key, got %s", fc.MatchedRule)
	}
}

func TestSecretScanner_DetectGitHubToken(t *testing.T) {
	f := NewSecretScannerFilter()
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"content":"token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}}}`)
	fc := NewFilterContext(raw, api.DirectionInbound)
	fc.Method = "tools/call"

	if err := f.Process(context.Background(), fc); err != nil {
		t.Fatal(err)
	}
	if fc.Verdict != api.VerdictDeny {
		t.Errorf("expected deny for GitHub token, got %s", fc.Verdict)
	}
}

func TestSecretScanner_DetectPrivateKey(t *testing.T) {
	f := NewSecretScannerFilter()
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"content":"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."}}}`)
	fc := NewFilterContext(raw, api.DirectionInbound)
	fc.Method = "tools/call"

	if err := f.Process(context.Background(), fc); err != nil {
		t.Fatal(err)
	}
	if fc.Verdict != api.VerdictDeny {
		t.Errorf("expected deny for private key, got %s", fc.Verdict)
	}
}

func TestSecretScanner_DetectStripeKey(t *testing.T) {
	f := NewSecretScannerFilter()
	// Use sk_test_ prefix which is the standard Stripe test mode prefix
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_command","arguments":{"command":"curl -H 'Authorization: Bearer sk_test_XXXXXXXXXXXXXXXXXXXXXXXXXXXX'"}}}`)
	fc := NewFilterContext(raw, api.DirectionInbound)
	fc.Method = "tools/call"

	if err := f.Process(context.Background(), fc); err != nil {
		t.Fatal(err)
	}
	if fc.Verdict != api.VerdictDeny {
		t.Errorf("expected deny for Stripe key, got %s", fc.Verdict)
	}
}

func TestSecretScanner_DetectJWT(t *testing.T) {
	f := NewSecretScannerFilter()
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"content":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}}}`)
	fc := NewFilterContext(raw, api.DirectionInbound)
	fc.Method = "tools/call"

	if err := f.Process(context.Background(), fc); err != nil {
		t.Fatal(err)
	}
	if fc.Verdict != api.VerdictDeny {
		t.Errorf("expected deny for JWT token, got %s", fc.Verdict)
	}
}

func TestSecretScanner_AllowSafeContent(t *testing.T) {
	f := NewSecretScannerFilter()
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/hello.txt","content":"Hello, World!"}}}`)
	fc := NewFilterContext(raw, api.DirectionInbound)
	fc.Method = "tools/call"

	if err := f.Process(context.Background(), fc); err != nil {
		t.Fatal(err)
	}
	// Should not set a deny verdict
	if fc.Verdict == api.VerdictDeny {
		t.Errorf("expected no deny for safe content, got deny (rule: %s)", fc.MatchedRule)
	}
}

func TestSecretScanner_SkipOutbound(t *testing.T) {
	f := NewSecretScannerFilter()
	raw := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":"AKIAIOSFODNN7EXAMPLE"}}`)
	fc := NewFilterContext(raw, api.DirectionOutbound)

	if err := f.Process(context.Background(), fc); err != nil {
		t.Fatal(err)
	}
	if fc.Halted {
		t.Error("expected outbound messages to be skipped")
	}
}

func TestSecretScanner_SkipHalted(t *testing.T) {
	f := NewSecretScannerFilter()
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_command","arguments":{"command":"AKIAIOSFODNN7EXAMPLE"}}}`)
	fc := NewFilterContext(raw, api.DirectionInbound)
	fc.Halted = true // Already denied

	if err := f.Process(context.Background(), fc); err != nil {
		t.Fatal(err)
	}
	// Should not change verdict since already halted
	if fc.MatchedRule != "" {
		t.Errorf("expected no rule match when halted, got %s", fc.MatchedRule)
	}
}

func TestSecretScanner_HighEntropy(t *testing.T) {
	f := NewSecretScannerFilter(WithEntropyThreshold(4.0))
	// A random-looking 40 char string
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"content":"aB3xK9mP2qR7wL5nJ8vC4hF6tY0uD1eG3sI"}}}`)
	fc := NewFilterContext(raw, api.DirectionInbound)
	fc.Method = "tools/call"
	fc.Arguments = []byte(`{"content":"aB3xK9mP2qR7wL5nJ8vC4hF6tY0uD1eG3sI"}`)

	if err := f.Process(context.Background(), fc); err != nil {
		t.Fatal(err)
	}
	if fc.Verdict != api.VerdictDeny {
		t.Errorf("expected deny for high-entropy string, got verdict=%s rule=%s", fc.Verdict, fc.MatchedRule)
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		input    string
		minBits  float64
		maxBits  float64
	}{
		{"aaaa", 0.0, 0.1},                     // All same char
		{"abcd", 1.9, 2.1},                     // 4 unique chars, uniform
		{"aB3xK9mP2qR7wL5nJ8vC4hF6t", 4.0, 5.0}, // High entropy
		{"", 0.0, 0.0},
	}

	for _, tt := range tests {
		e := shannonEntropy(tt.input)
		if e < tt.minBits || e > tt.maxBits {
			t.Errorf("shannonEntropy(%q) = %.2f, expected [%.1f, %.1f]", tt.input, e, tt.minBits, tt.maxBits)
		}
	}
}

func TestExtractStringTokens(t *testing.T) {
	tokens := extractStringTokens(`{"key": "value", "nested": "hello world"}`)
	if len(tokens) != 4 {
		t.Errorf("expected 4 tokens, got %d: %v", len(tokens), tokens)
	}
}
