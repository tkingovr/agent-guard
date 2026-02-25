package filter

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/aqubia/agent-guard/api"
	"github.com/aqubia/agent-guard/internal/policy"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(nil, nil))
}

func TestFilterChain_ParseAndPolicy(t *testing.T) {
	pf := &policy.PolicyFile{
		Version: 1,
		Settings: policy.Settings{
			DefaultAction: api.VerdictDeny,
		},
		Rules: []policy.Rule{
			{
				Name:   "allow-initialize",
				Match:  policy.RuleMatch{Method: "initialize"},
				Action: "allow",
			},
		},
	}
	engine, err := policy.NewYAMLEngineFromPolicy(pf)
	if err != nil {
		t.Fatal(err)
	}

	chain := NewChain(newTestLogger(),
		NewParseFilter(),
		NewPolicyFilter(engine),
	)

	// Test allowed request
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	fc := NewFilterContext(raw, api.DirectionInbound)
	if err := chain.Process(context.Background(), fc); err != nil {
		t.Fatal(err)
	}
	if fc.Verdict != api.VerdictAllow {
		t.Errorf("expected allow, got %s", fc.Verdict)
	}
	if fc.Halted {
		t.Error("expected not halted for allow")
	}

	// Test denied request
	raw = []byte(`{"jsonrpc":"2.0","id":2,"method":"unknown/method"}`)
	fc = NewFilterContext(raw, api.DirectionInbound)
	if err := chain.Process(context.Background(), fc); err != nil {
		t.Fatal(err)
	}
	if fc.Verdict != api.VerdictDeny {
		t.Errorf("expected deny, got %s", fc.Verdict)
	}
	if !fc.Halted {
		t.Error("expected halted for deny")
	}
}

func TestFilterChain_ToolCall(t *testing.T) {
	pf := &policy.PolicyFile{
		Version: 1,
		Settings: policy.Settings{
			DefaultAction: api.VerdictDeny,
		},
		Rules: []policy.Rule{
			{
				Name:   "allow-read",
				Match:  policy.RuleMatch{Method: "tools/call", Tool: "read_file"},
				Action: "allow",
			},
		},
	}
	engine, err := policy.NewYAMLEngineFromPolicy(pf)
	if err != nil {
		t.Fatal(err)
	}

	chain := NewChain(newTestLogger(),
		NewParseFilter(),
		NewPolicyFilter(engine),
	)

	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test"}}}`)
	fc := NewFilterContext(raw, api.DirectionInbound)
	if err := chain.Process(context.Background(), fc); err != nil {
		t.Fatal(err)
	}
	if fc.Tool != "read_file" {
		t.Errorf("expected tool read_file, got %q", fc.Tool)
	}
	if fc.Verdict != api.VerdictAllow {
		t.Errorf("expected allow, got %s", fc.Verdict)
	}
}

func TestFilterContext_ToAuditRecord(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test_tool","arguments":{"key":"val"}}}`)
	fc := NewFilterContext(raw, api.DirectionInbound)
	fc.Method = "tools/call"
	fc.Tool = "test_tool"
	fc.Arguments = json.RawMessage(`{"key":"val"}`)
	fc.Verdict = api.VerdictAllow
	fc.MatchedRule = "test-rule"

	record := fc.ToAuditRecord()
	if record.Method != "tools/call" {
		t.Errorf("expected method tools/call, got %s", record.Method)
	}
	if record.Tool != "test_tool" {
		t.Errorf("expected tool test_tool, got %s", record.Tool)
	}
	if record.Verdict != api.VerdictAllow {
		t.Errorf("expected verdict allow, got %s", record.Verdict)
	}
	if record.RawSize != len(raw) {
		t.Errorf("expected raw size %d, got %d", len(raw), record.RawSize)
	}
}

func TestOutboundParseFilter(t *testing.T) {
	f := NewOutboundParseFilter()
	raw := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
	fc := NewFilterContext(raw, api.DirectionOutbound)
	if err := f.Process(context.Background(), fc); err != nil {
		t.Fatal(err)
	}
	if fc.Verdict != api.VerdictAllow {
		t.Errorf("expected allow for outbound, got %s", fc.Verdict)
	}
}
