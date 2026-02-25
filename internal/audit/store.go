package audit

import (
	"context"

	"github.com/aqubia/agent-guard/api"
)

// Store defines the interface for audit record persistence and retrieval.
type Store interface {
	// Write appends an audit record.
	Write(ctx context.Context, record *api.AuditRecord) error

	// Query retrieves audit records matching the filter.
	Query(ctx context.Context, filter api.QueryFilter) ([]*api.AuditRecord, error)

	// Stats returns aggregate statistics.
	Stats(ctx context.Context) (*api.AuditStats, error)

	// Subscribe returns a channel that receives new audit records in real time.
	// The returned function cancels the subscription.
	Subscribe(ctx context.Context) (<-chan *api.AuditRecord, func())

	// Close shuts down the store and flushes any buffers.
	Close() error
}
