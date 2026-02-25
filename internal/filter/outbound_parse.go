package filter

import (
	"context"
	"encoding/json"

	"github.com/tkingovr/agent-guard/api"
)

// OutboundParseFilter does lightweight parsing of outbound (server→client) messages.
// It doesn't extract tool info since outbound messages are responses.
type OutboundParseFilter struct{}

func NewOutboundParseFilter() *OutboundParseFilter { return &OutboundParseFilter{} }
func (f *OutboundParseFilter) Name() string         { return "outbound_parse" }

func (f *OutboundParseFilter) Process(_ context.Context, fc *FilterContext) error {
	var msg api.JSONRPCMessage
	if err := json.Unmarshal(fc.Raw, &msg); err != nil {
		// Not valid JSON-RPC, just log and allow
		fc.Verdict = api.VerdictAllow
		return nil
	}
	fc.Message = &msg
	fc.Method = msg.Method
	fc.Verdict = api.VerdictAllow
	return nil
}
