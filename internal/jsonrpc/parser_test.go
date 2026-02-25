package jsonrpc

import (
	"encoding/json"
	"testing"
)

func TestParse_ValidRequest(t *testing.T) {
	data := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test"}}}`)
	msg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.Method != "tools/call" {
		t.Errorf("expected method tools/call, got %q", msg.Method)
	}
	if !msg.IsRequest() {
		t.Error("expected IsRequest() to be true")
	}
	if msg.IsNotification() {
		t.Error("expected IsNotification() to be false")
	}
}

func TestParse_Notification(t *testing.T) {
	data := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	msg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !msg.IsNotification() {
		t.Error("expected IsNotification() to be true")
	}
	if msg.IsRequest() {
		t.Error("expected IsRequest() to be false")
	}
}

func TestParse_Response(t *testing.T) {
	data := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
	msg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !msg.IsResponse() {
		t.Error("expected IsResponse() to be true")
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	data := []byte(`not json`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParse_WrongVersion(t *testing.T) {
	data := []byte(`{"jsonrpc":"1.0","id":1,"method":"test"}`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error for wrong version")
	}
}

func TestExtractToolCall(t *testing.T) {
	data := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test"}}}`)
	msg, _ := Parse(data)

	tc, err := ExtractToolCall(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc.Name != "read_file" {
		t.Errorf("expected tool name read_file, got %q", tc.Name)
	}

	args, err := ExtractArguments(tc.Arguments)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if args["path"] != "/tmp/test" {
		t.Errorf("expected path /tmp/test, got %v", args["path"])
	}
}

func TestExtractToolCall_WrongMethod(t *testing.T) {
	data := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	msg, _ := Parse(data)
	_, err := ExtractToolCall(msg)
	if err == nil {
		t.Fatal("expected error for non tools/call method")
	}
}

func TestMarshalDenyResponse(t *testing.T) {
	resp := NewDenyResponse(json.RawMessage(`1`), "access denied")
	data, err := Marshal(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var msg map[string]any
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	errObj, ok := msg["error"].(map[string]any)
	if !ok {
		t.Fatal("expected error field in response")
	}
	if errObj["message"] != "access denied" {
		t.Errorf("expected message 'access denied', got %v", errObj["message"])
	}
	if int(errObj["code"].(float64)) != ErrorCodePolicyDenied {
		t.Errorf("expected error code %d, got %v", ErrorCodePolicyDenied, errObj["code"])
	}
}
