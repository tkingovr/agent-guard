package jsonrpc

import (
	"encoding/json"
	"fmt"

	"github.com/tkingovr/agent-guard/api"
)

// Parse decodes a raw JSON byte slice into a JSONRPCMessage.
func Parse(data []byte) (*api.JSONRPCMessage, error) {
	var msg api.JSONRPCMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC message: %w", err)
	}
	if msg.JSONRPC != "2.0" {
		return nil, fmt.Errorf("unsupported JSON-RPC version: %q", msg.JSONRPC)
	}
	return &msg, nil
}

// ExtractToolCall extracts tool name and arguments from a tools/call request.
func ExtractToolCall(msg *api.JSONRPCMessage) (*api.ToolCallParams, error) {
	if msg.Method != "tools/call" {
		return nil, fmt.Errorf("not a tools/call request: %q", msg.Method)
	}
	if msg.Params == nil {
		return nil, fmt.Errorf("tools/call request has no params")
	}
	var params api.ToolCallParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return nil, fmt.Errorf("failed to parse tools/call params: %w", err)
	}
	return &params, nil
}

// ExtractArguments unmarshals arguments into a map for policy matching.
func ExtractArguments(raw json.RawMessage) (map[string]any, error) {
	if raw == nil {
		return nil, nil
	}
	var args map[string]any
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("failed to parse arguments: %w", err)
	}
	return args, nil
}
