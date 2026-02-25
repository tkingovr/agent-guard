package filter

import (
	"context"
	"fmt"
	"log/slog"
)

// Chain executes a sequence of filters in order.
type Chain struct {
	filters []Filter
	logger  *slog.Logger
}

// NewChain creates a new filter chain.
func NewChain(logger *slog.Logger, filters ...Filter) *Chain {
	return &Chain{
		filters: filters,
		logger:  logger,
	}
}

// Process runs all filters in sequence on the given context.
// If any filter sets fc.Halted to true, remaining filters still
// run (e.g., audit) but the verdict is final.
func (c *Chain) Process(ctx context.Context, fc *FilterContext) error {
	for _, f := range c.filters {
		if err := f.Process(ctx, fc); err != nil {
			return fmt.Errorf("filter %q: %w", f.Name(), err)
		}
		c.logger.Debug("filter executed",
			"filter", f.Name(),
			"method", fc.Method,
			"verdict", fc.Verdict,
			"halted", fc.Halted,
		)
	}
	return nil
}

// AddFilter appends a filter to the chain.
func (c *Chain) AddFilter(f Filter) {
	c.filters = append(c.filters, f)
}
