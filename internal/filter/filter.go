package filter

import "context"

// Filter is a single step in the request processing pipeline.
type Filter interface {
	// Name returns the filter name for logging.
	Name() string

	// Process processes the filter context. It may modify the context
	// (e.g., set verdict, add metadata) or produce side effects (e.g., audit logging).
	// Returning an error aborts the filter chain.
	Process(ctx context.Context, fc *FilterContext) error
}
