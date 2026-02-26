package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/topdown"

	"github.com/tkingovr/agent-guard/api"
)

// OPAEngine implements the Engine interface using embedded OPA/Rego.
type OPAEngine struct {
	mu   sync.RWMutex
	path string

	// Compiled query for evaluation
	query rego.PreparedEvalQuery
}

// NewOPAEngine creates a new OPA engine from a .rego policy file.
func NewOPAEngine(path string) (*OPAEngine, error) {
	e := &OPAEngine{path: path}
	if err := e.Reload(context.Background()); err != nil {
		return nil, err
	}
	return e, nil
}

// NewOPAEngineFromSource creates a new OPA engine from raw Rego source.
func NewOPAEngineFromSource(source string) (*OPAEngine, error) {
	e := &OPAEngine{}
	if err := e.loadSource(source); err != nil {
		return nil, err
	}
	return e, nil
}

// Evaluate runs the OPA policy against the given input.
//
// The Rego policy must define the following in package agentguard:
//
//	verdict: "allow" | "deny" | "ask" | "log"
//	rule_name: string (optional)
//	message: string (optional)
//
// Input available to the policy:
//
//	input.method: string
//	input.tool: string
//	input.arguments: object
func (e *OPAEngine) Evaluate(ctx context.Context, input *EvalInput) (*EvalResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Build input map
	inputMap := map[string]any{
		"method": input.Method,
		"tool":   input.Tool,
	}
	if input.Arguments != nil {
		var args any
		if err := json.Unmarshal(input.Arguments, &args); err == nil {
			inputMap["arguments"] = args
		}
	}

	rs, err := e.query.Eval(ctx, rego.EvalInput(inputMap))
	if err != nil {
		// If evaluation fails due to undefined, return deny
		if topdown.IsError(err) {
			return &EvalResult{
				Verdict: api.VerdictDeny,
				Rule:    "_opa_error",
				Message: "OPA evaluation error: " + err.Error(),
			}, nil
		}
		return nil, fmt.Errorf("OPA evaluation failed: %w", err)
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return &EvalResult{
			Verdict: api.VerdictDeny,
			Rule:    "_opa_default",
			Message: "OPA policy returned no result",
		}, nil
	}

	// The result is a map from the full object query
	resultMap, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return &EvalResult{
			Verdict: api.VerdictDeny,
			Rule:    "_opa_parse_error",
			Message: "unexpected OPA result type",
		}, nil
	}

	return parseOPAResult(resultMap), nil
}

// Reload re-reads the Rego policy file from disk and recompiles.
func (e *OPAEngine) Reload(_ context.Context) error {
	if e.path == "" {
		return nil
	}
	data, err := os.ReadFile(e.path)
	if err != nil {
		return fmt.Errorf("reading OPA policy file: %w", err)
	}
	return e.loadSource(string(data))
}

func (e *OPAEngine) loadSource(source string) error {
	// Parse to validate
	_, err := ast.ParseModuleWithOpts("policy.rego", source, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		return fmt.Errorf("parsing Rego policy: %w", err)
	}

	store := inmem.New()

	r := rego.New(
		rego.Query("data.agentguard"),
		rego.Module("policy.rego", source),
		rego.Store(store),
	)

	query, err := r.PrepareForEval(context.Background())
	if err != nil {
		return fmt.Errorf("preparing OPA query: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.query = query

	return nil
}

func parseOPAResult(m map[string]any) *EvalResult {
	result := &EvalResult{
		Verdict: api.VerdictDeny, // default if not set
	}

	if v, ok := m["verdict"].(string); ok {
		switch v {
		case "allow":
			result.Verdict = api.VerdictAllow
		case "deny":
			result.Verdict = api.VerdictDeny
		case "ask":
			result.Verdict = api.VerdictAsk
		case "log":
			result.Verdict = api.VerdictLog
		}
	}

	if r, ok := m["rule_name"].(string); ok {
		result.Rule = r
	}
	if msg, ok := m["message"].(string); ok {
		result.Message = msg
	}

	return result
}
