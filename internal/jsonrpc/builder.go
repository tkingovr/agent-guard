package jsonrpc

import (
	"encoding/json"

	"github.com/aqubia/agent-guard/api"
)

// ErrorCodePolicyDenied is a custom JSON-RPC error code for policy denials.
const ErrorCodePolicyDenied = -32001

// ErrorCodeApprovalTimeout is a custom JSON-RPC error code for approval timeouts.
const ErrorCodeApprovalTimeout = -32002

// NewDenyResponse creates a JSON-RPC error response for a denied request.
func NewDenyResponse(id json.RawMessage, message string) *api.JSONRPCMessage {
	return &api.JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      id,
		Error: &api.JSONRPCError{
			Code:    ErrorCodePolicyDenied,
			Message: message,
		},
	}
}

// NewApprovalTimeoutResponse creates a JSON-RPC error response for an approval timeout.
func NewApprovalTimeoutResponse(id json.RawMessage) *api.JSONRPCMessage {
	return &api.JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      id,
		Error: &api.JSONRPCError{
			Code:    ErrorCodeApprovalTimeout,
			Message: "approval request timed out",
		},
	}
}

// Marshal encodes a JSONRPCMessage to JSON bytes.
func Marshal(msg *api.JSONRPCMessage) ([]byte, error) {
	return json.Marshal(msg)
}
