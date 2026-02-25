package policy

import "context"

// Engine is the interface for policy evaluation backends.
type Engine interface {
	// Evaluate checks a request against loaded policies and returns a verdict.
	Evaluate(ctx context.Context, input *EvalInput) (*EvalResult, error)

	// Reload reloads policies from the source (file, remote, etc.).
	Reload(ctx context.Context) error
}
