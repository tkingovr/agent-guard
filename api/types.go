package api

import (
	"encoding/json"
	"time"
)

// Verdict represents the outcome of a policy evaluation.
type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictDeny  Verdict = "deny"
	VerdictAsk   Verdict = "ask"
	VerdictLog   Verdict = "log"
)

// Direction indicates whether a message is from client→server or server→client.
type Direction string

const (
	DirectionInbound  Direction = "inbound"  // client → server
	DirectionOutbound Direction = "outbound" // server → client
)

// AuditRecord represents a single audited action.
type AuditRecord struct {
	ID        string          `json:"id"`
	Timestamp time.Time       `json:"timestamp"`
	Direction Direction       `json:"direction"`
	Method    string          `json:"method,omitempty"`
	Tool      string          `json:"tool,omitempty"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	Verdict   Verdict         `json:"verdict"`
	Rule      string          `json:"rule,omitempty"`
	Message   string          `json:"message,omitempty"`
	RawSize   int             `json:"raw_size,omitempty"`
	Duration  time.Duration   `json:"duration,omitempty"`
}

// CheckRequest is used by the CLI `check` command and SDK API.
type CheckRequest struct {
	Method    string          `json:"method"`
	Tool      string          `json:"tool,omitempty"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// CheckResponse is the result of a policy check.
type CheckResponse struct {
	Verdict Verdict `json:"verdict"`
	Rule    string  `json:"rule,omitempty"`
	Message string  `json:"message,omitempty"`
}
