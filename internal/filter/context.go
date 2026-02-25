package filter

import (
	"encoding/json"
	"time"

	"github.com/aqubia/agent-guard/api"
)

// FilterContext carries all metadata through the filter chain for a single message.
type FilterContext struct {
	// Raw is the original raw JSON bytes.
	Raw []byte

	// Message is the parsed JSON-RPC message.
	Message *api.JSONRPCMessage

	// Direction indicates inbound (client→server) or outbound (server→client).
	Direction api.Direction

	// Method is the JSON-RPC method (extracted by ParseFilter).
	Method string

	// Tool is the tool name for tools/call requests (extracted by ParseFilter).
	Tool string

	// Arguments is the raw JSON arguments for tools/call requests.
	Arguments json.RawMessage

	// Verdict is set by the PolicyFilter after evaluation.
	Verdict api.Verdict

	// MatchedRule is the name of the rule that matched.
	MatchedRule string

	// VerdictMessage is the human-readable message from the matched rule.
	VerdictMessage string

	// StartTime records when the message entered the pipeline.
	StartTime time.Time

	// Halted indicates the pipeline should stop (deny/ask was decided).
	Halted bool
}

// NewFilterContext creates a new FilterContext for a raw message.
func NewFilterContext(raw []byte, direction api.Direction) *FilterContext {
	return &FilterContext{
		Raw:       raw,
		Direction: direction,
		StartTime: time.Now(),
	}
}

// ToAuditRecord converts the filter context into an audit record.
func (fc *FilterContext) ToAuditRecord() *api.AuditRecord {
	return &api.AuditRecord{
		Timestamp: fc.StartTime,
		Direction: fc.Direction,
		Method:    fc.Method,
		Tool:      fc.Tool,
		Arguments: fc.Arguments,
		Verdict:   fc.Verdict,
		Rule:      fc.MatchedRule,
		Message:   fc.VerdictMessage,
		RawSize:   len(fc.Raw),
		Duration:  time.Since(fc.StartTime),
	}
}
