package approval

import (
	"context"
	"testing"
	"time"

	"github.com/tkingovr/agent-guard/api"
)

func TestQueue_SubmitAndApprove(t *testing.T) {
	q := NewQueue(10 * time.Second)

	var verdict api.Verdict
	var submitErr error
	done := make(chan struct{})

	go func() {
		verdict, submitErr = q.Submit(context.Background(), "tools/call", "write_file", "ask-write", "needs approval", nil)
		close(done)
	}()

	// Wait a moment for the request to be queued
	time.Sleep(50 * time.Millisecond)

	pending := q.Pending()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending request, got %d", len(pending))
	}

	if err := q.Approve(pending[0].ID); err != nil {
		t.Fatal(err)
	}

	<-done
	if submitErr != nil {
		t.Fatal(submitErr)
	}
	if verdict != api.VerdictAllow {
		t.Errorf("expected allow after approval, got %s", verdict)
	}
}

func TestQueue_SubmitAndDeny(t *testing.T) {
	q := NewQueue(10 * time.Second)

	var verdict api.Verdict
	done := make(chan struct{})

	go func() {
		verdict, _ = q.Submit(context.Background(), "tools/call", "delete_file", "ask-delete", "needs approval", nil)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	pending := q.Pending()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}

	if err := q.Deny(pending[0].ID); err != nil {
		t.Fatal(err)
	}

	<-done
	if verdict != api.VerdictDeny {
		t.Errorf("expected deny, got %s", verdict)
	}
}

func TestQueue_Timeout(t *testing.T) {
	q := NewQueue(100 * time.Millisecond)

	verdict, err := q.Submit(context.Background(), "tools/call", "write_file", "ask-write", "needs approval", nil)
	if err != nil {
		t.Fatal(err)
	}
	if verdict != api.VerdictDeny {
		t.Errorf("expected deny on timeout, got %s", verdict)
	}
}

func TestQueue_ContextCancellation(t *testing.T) {
	q := NewQueue(10 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	verdict, err := q.Submit(ctx, "tools/call", "write_file", "ask-write", "needs approval", nil)
	if err == nil {
		t.Fatal("expected error on context cancellation")
	}
	if verdict != api.VerdictDeny {
		t.Errorf("expected deny on context cancel, got %s", verdict)
	}
}

func TestQueue_DoubleResolve(t *testing.T) {
	q := NewQueue(10 * time.Second)

	go func() {
		q.Submit(context.Background(), "tools/call", "test", "rule", "msg", nil)
	}()
	time.Sleep(50 * time.Millisecond)

	pending := q.Pending()
	if err := q.Approve(pending[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := q.Approve(pending[0].ID); err == nil {
		t.Fatal("expected error for double resolve")
	}
}

func TestQueue_Subscribe(t *testing.T) {
	q := NewQueue(10 * time.Second)

	ch, cancel := q.Subscribe()
	defer cancel()

	go func() {
		q.Submit(context.Background(), "tools/call", "test", "rule", "msg", nil)
	}()

	select {
	case req := <-ch:
		if req.Tool != "test" {
			t.Errorf("expected tool test, got %s", req.Tool)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for subscription")
	}

	// Clean up: approve the pending request
	pending := q.Pending()
	if len(pending) > 0 {
		q.Approve(pending[0].ID)
	}
}
