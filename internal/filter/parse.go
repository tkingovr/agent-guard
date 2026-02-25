package filter

import (
	"context"

	"github.com/tkingovr/agent-guard/internal/jsonrpc"
)

// ParseFilter extracts method, tool, and arguments from the raw JSON-RPC message.
type ParseFilter struct{}

func NewParseFilter() *ParseFilter { return &ParseFilter{} }
func (f *ParseFilter) Name() string { return "parse" }

func (f *ParseFilter) Process(_ context.Context, fc *FilterContext) error {
	msg, err := jsonrpc.Parse(fc.Raw)
	if err != nil {
		return err
	}
	fc.Message = msg
	fc.Method = msg.Method

	// For tools/call, extract tool name and arguments
	if msg.Method == "tools/call" {
		tc, err := jsonrpc.ExtractToolCall(msg)
		if err != nil {
			return err
		}
		fc.Tool = tc.Name
		fc.Arguments = tc.Arguments
	}

	return nil
}
