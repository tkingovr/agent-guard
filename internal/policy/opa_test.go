package policy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/tkingovr/agent-guard/api"
)

const testRegoPolicy = `package agentguard

import rego.v1

default verdict := "deny"
default rule_name := "_default"
default message := "default deny"

verdict := "allow" if {
	input.method == "initialize"
}
rule_name := "allow-init" if {
	input.method == "initialize"
}

verdict := "allow" if {
	input.method == "tools/list"
}
rule_name := "allow-tools-list" if {
	input.method == "tools/list"
}

verdict := "allow" if {
	input.method == "tools/call"
	input.tool == "read_file"
	not has_ssh_path
}
rule_name := "allow-read-file" if {
	input.method == "tools/call"
	input.tool == "read_file"
	not has_ssh_path
}

verdict := "deny" if {
	input.method == "tools/call"
	has_ssh_path
}
rule_name := "block-ssh" if {
	input.method == "tools/call"
	has_ssh_path
}
message := "SSH key access blocked" if {
	input.method == "tools/call"
	has_ssh_path
}

verdict := "ask" if {
	input.method == "tools/call"
	input.tool == "write_file"
	not has_ssh_path
}
rule_name := "ask-write-file" if {
	input.method == "tools/call"
	input.tool == "write_file"
	not has_ssh_path
}
message := "File write requires approval" if {
	input.method == "tools/call"
	input.tool == "write_file"
	not has_ssh_path
}

has_ssh_path if {
	some k, v in input.arguments
	contains(v, ".ssh/")
}
`

func TestOPAEngine_AllowInitialize(t *testing.T) {
	engine, err := NewOPAEngineFromSource(testRegoPolicy)
	if err != nil {
		t.Fatal(err)
	}

	result, err := engine.Evaluate(context.Background(), &EvalInput{
		Method: "initialize",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != api.VerdictAllow {
		t.Errorf("expected allow, got %s", result.Verdict)
	}
	if result.Rule != "allow-init" {
		t.Errorf("expected rule allow-init, got %s", result.Rule)
	}
}

func TestOPAEngine_AllowToolsList(t *testing.T) {
	engine, err := NewOPAEngineFromSource(testRegoPolicy)
	if err != nil {
		t.Fatal(err)
	}

	result, err := engine.Evaluate(context.Background(), &EvalInput{
		Method: "tools/list",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != api.VerdictAllow {
		t.Errorf("expected allow, got %s", result.Verdict)
	}
}

func TestOPAEngine_AllowReadFile(t *testing.T) {
	engine, err := NewOPAEngineFromSource(testRegoPolicy)
	if err != nil {
		t.Fatal(err)
	}

	result, err := engine.Evaluate(context.Background(), &EvalInput{
		Method:    "tools/call",
		Tool:      "read_file",
		Arguments: json.RawMessage(`{"path":"/tmp/test.txt"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != api.VerdictAllow {
		t.Errorf("expected allow, got %s (rule: %s, msg: %s)", result.Verdict, result.Rule, result.Message)
	}
}

func TestOPAEngine_DenySSHKeys(t *testing.T) {
	engine, err := NewOPAEngineFromSource(testRegoPolicy)
	if err != nil {
		t.Fatal(err)
	}

	result, err := engine.Evaluate(context.Background(), &EvalInput{
		Method:    "tools/call",
		Tool:      "read_file",
		Arguments: json.RawMessage(`{"path":"/home/user/.ssh/id_rsa"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != api.VerdictDeny {
		t.Errorf("expected deny, got %s (rule: %s)", result.Verdict, result.Rule)
	}
	if result.Rule != "block-ssh" {
		t.Errorf("expected rule block-ssh, got %s", result.Rule)
	}
}

func TestOPAEngine_AskWriteFile(t *testing.T) {
	engine, err := NewOPAEngineFromSource(testRegoPolicy)
	if err != nil {
		t.Fatal(err)
	}

	result, err := engine.Evaluate(context.Background(), &EvalInput{
		Method:    "tools/call",
		Tool:      "write_file",
		Arguments: json.RawMessage(`{"path":"/tmp/out.txt","content":"hello"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != api.VerdictAsk {
		t.Errorf("expected ask, got %s (rule: %s, msg: %s)", result.Verdict, result.Rule, result.Message)
	}
}

func TestOPAEngine_DefaultDeny(t *testing.T) {
	engine, err := NewOPAEngineFromSource(testRegoPolicy)
	if err != nil {
		t.Fatal(err)
	}

	result, err := engine.Evaluate(context.Background(), &EvalInput{
		Method: "unknown/method",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != api.VerdictDeny {
		t.Errorf("expected deny, got %s", result.Verdict)
	}
}

func TestOPAEngine_InvalidRego(t *testing.T) {
	_, err := NewOPAEngineFromSource("this is not valid rego {{{")
	if err == nil {
		t.Fatal("expected error for invalid Rego")
	}
}

func TestOPAEngine_FromFile(t *testing.T) {
	engine, err := NewOPAEngine("../../testdata/policies/example.rego")
	if err != nil {
		t.Fatal(err)
	}

	result, err := engine.Evaluate(context.Background(), &EvalInput{Method: "initialize"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != api.VerdictAllow {
		t.Errorf("expected allow, got %s", result.Verdict)
	}
}
