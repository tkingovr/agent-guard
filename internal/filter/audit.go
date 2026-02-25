package filter

import (
	"context"

	"github.com/tkingovr/agent-guard/internal/audit"
)

// AuditFilter writes an audit record for every processed message.
type AuditFilter struct {
	store audit.Store
}

func NewAuditFilter(store audit.Store) *AuditFilter {
	return &AuditFilter{store: store}
}

func (f *AuditFilter) Name() string { return "audit" }

func (f *AuditFilter) Process(ctx context.Context, fc *FilterContext) error {
	record := fc.ToAuditRecord()
	return f.store.Write(ctx, record)
}
