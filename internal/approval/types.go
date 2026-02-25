package approval

import (
	"encoding/json"
	"time"

	"github.com/aqubia/agent-guard/api"
)

// Status represents the state of an approval request.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusTimedOut Status = "timed_out"
)

// Request represents a pending human approval request.
type Request struct {
	ID        string          `json:"id"`
	CreatedAt time.Time       `json:"created_at"`
	Method    string          `json:"method"`
	Tool      string          `json:"tool,omitempty"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	Message   string          `json:"message"`
	Rule      string          `json:"rule"`
	Status    Status          `json:"status"`
	Verdict   api.Verdict     `json:"verdict,omitempty"`
	DecidedAt *time.Time      `json:"decided_at,omitempty"`

	// done is signaled when the request is resolved
	done chan struct{}
}

// Wait blocks until the request is resolved or the context is canceled.
func (r *Request) Wait() <-chan struct{} {
	return r.done
}
