package approval

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/tkingovr/agent-guard/api"
)

// Queue manages pending approval requests.
type Queue struct {
	mu       sync.RWMutex
	requests map[string]*Request
	timeout  time.Duration
	nextID   int

	// Subscribers for real-time updates
	subMu   sync.RWMutex
	subs    map[int]chan *Request
	nextSub int
}

// NewQueue creates a new approval queue with the given timeout.
func NewQueue(timeout time.Duration) *Queue {
	return &Queue{
		requests: make(map[string]*Request),
		timeout:  timeout,
		subs:     make(map[int]chan *Request),
	}
}

// Submit creates a new approval request and blocks until it's resolved or times out.
func (q *Queue) Submit(ctx context.Context, method, tool, rule, message string, args []byte) (api.Verdict, error) {
	req := q.enqueue(method, tool, rule, message, args)

	// Notify subscribers
	q.notifySubscribers(req)

	// Wait for resolution or timeout
	select {
	case <-req.Wait():
		q.mu.RLock()
		defer q.mu.RUnlock()
		if req.Status == StatusApproved {
			return api.VerdictAllow, nil
		}
		return api.VerdictDeny, nil

	case <-time.After(q.timeout):
		q.mu.Lock()
		req.Status = StatusTimedOut
		now := time.Now()
		req.DecidedAt = &now
		q.mu.Unlock()
		return api.VerdictDeny, nil

	case <-ctx.Done():
		return api.VerdictDeny, ctx.Err()
	}
}

func (q *Queue) enqueue(method, tool, rule, message string, args []byte) *Request {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.nextID++
	req := &Request{
		ID:        fmt.Sprintf("approval-%d", q.nextID),
		CreatedAt: time.Now(),
		Method:    method,
		Tool:      tool,
		Arguments: args,
		Message:   message,
		Rule:      rule,
		Status:    StatusPending,
		done:      make(chan struct{}),
	}
	q.requests[req.ID] = req
	return req
}

// Approve marks a request as approved.
func (q *Queue) Approve(id string) error {
	return q.resolve(id, StatusApproved)
}

// Deny marks a request as denied.
func (q *Queue) Deny(id string) error {
	return q.resolve(id, StatusDenied)
}

func (q *Queue) resolve(id string, status Status) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	req, ok := q.requests[id]
	if !ok {
		return fmt.Errorf("approval request %q not found", id)
	}
	if req.Status != StatusPending {
		return fmt.Errorf("approval request %q already resolved: %s", id, req.Status)
	}

	req.Status = status
	now := time.Now()
	req.DecidedAt = &now

	if status == StatusApproved {
		req.Verdict = api.VerdictAllow
	} else {
		req.Verdict = api.VerdictDeny
	}

	close(req.done)
	return nil
}

// Pending returns all pending approval requests.
func (q *Queue) Pending() []*Request {
	q.mu.RLock()
	defer q.mu.RUnlock()

	var pending []*Request
	for _, req := range q.requests {
		if req.Status == StatusPending {
			pending = append(pending, req)
		}
	}
	return pending
}

// All returns all requests (for dashboard history).
func (q *Queue) All() []*Request {
	q.mu.RLock()
	defer q.mu.RUnlock()

	all := make([]*Request, 0, len(q.requests))
	for _, req := range q.requests {
		all = append(all, req)
	}
	return all
}

// Subscribe returns a channel that receives new approval requests.
func (q *Queue) Subscribe() (<-chan *Request, func()) {
	q.subMu.Lock()
	defer q.subMu.Unlock()

	ch := make(chan *Request, 50)
	id := q.nextSub
	q.nextSub++
	q.subs[id] = ch

	cancel := func() {
		q.subMu.Lock()
		defer q.subMu.Unlock()
		delete(q.subs, id)
		close(ch)
	}

	return ch, cancel
}

func (q *Queue) notifySubscribers(req *Request) {
	q.subMu.RLock()
	defer q.subMu.RUnlock()

	for _, ch := range q.subs {
		select {
		case ch <- req:
		default:
		}
	}
}
