package filter

import (
	"context"

	"github.com/aqubia/agent-guard/api"
	"github.com/aqubia/agent-guard/internal/policy"
)

// PolicyFilter evaluates the request against the policy engine.
type PolicyFilter struct {
	engine policy.Engine
}

func NewPolicyFilter(engine policy.Engine) *PolicyFilter {
	return &PolicyFilter{engine: engine}
}

func (f *PolicyFilter) Name() string { return "policy" }

func (f *PolicyFilter) Process(ctx context.Context, fc *FilterContext) error {
	// Only evaluate inbound requests with a method
	if fc.Direction != api.DirectionInbound || fc.Method == "" {
		fc.Verdict = api.VerdictAllow
		return nil
	}

	// Only evaluate requests (not responses)
	if fc.Message != nil && fc.Message.IsResponse() {
		fc.Verdict = api.VerdictAllow
		return nil
	}

	input := &policy.EvalInput{
		Method:    fc.Method,
		Tool:      fc.Tool,
		Arguments: fc.Arguments,
	}

	result, err := f.engine.Evaluate(ctx, input)
	if err != nil {
		return err
	}

	fc.Verdict = result.Verdict
	fc.MatchedRule = result.Rule
	fc.VerdictMessage = result.Message

	if fc.Verdict == api.VerdictDeny || fc.Verdict == api.VerdictAsk {
		fc.Halted = true
	}

	return nil
}
