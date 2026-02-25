package api

import "encoding/json"

// JSONRPCMessage represents a JSON-RPC 2.0 message (request, response, or notification).
type JSONRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError represents a JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// IsRequest returns true if this message is a request (has method and ID).
func (m *JSONRPCMessage) IsRequest() bool {
	return m.Method != "" && m.ID != nil
}

// IsNotification returns true if this message is a notification (has method but no ID).
func (m *JSONRPCMessage) IsNotification() bool {
	return m.Method != "" && m.ID == nil
}

// IsResponse returns true if this message is a response (has ID but no method).
func (m *JSONRPCMessage) IsResponse() bool {
	return m.Method == "" && m.ID != nil
}

// ToolCallParams extracts tool name and arguments from a tools/call request.
type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}
