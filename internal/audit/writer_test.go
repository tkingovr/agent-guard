package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tkingovr/agent-guard/api"
)

func TestJSONLStore_WriteAndQuery(t *testing.T) {
	dir := t.TempDir()
	store, err := NewJSONLStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()

	// Write a record
	record := &api.AuditRecord{
		Timestamp: time.Now(),
		Direction: api.DirectionInbound,
		Method:    "tools/call",
		Tool:      "read_file",
		Verdict:   api.VerdictAllow,
		Rule:      "allow-read",
	}
	if err := store.Write(ctx, record); err != nil {
		t.Fatal(err)
	}

	// Query all
	results, err := store.Query(ctx, api.QueryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Method != "tools/call" {
		t.Errorf("expected method tools/call, got %s", results[0].Method)
	}
}

func TestJSONLStore_QueryFilter(t *testing.T) {
	dir := t.TempDir()
	store, err := NewJSONLStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()

	// Write multiple records
	records := []*api.AuditRecord{
		{Timestamp: time.Now(), Method: "tools/call", Tool: "read_file", Verdict: api.VerdictAllow},
		{Timestamp: time.Now(), Method: "tools/call", Tool: "write_file", Verdict: api.VerdictDeny},
		{Timestamp: time.Now(), Method: "initialize", Verdict: api.VerdictAllow},
	}
	for _, r := range records {
		if err := store.Write(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	// Filter by verdict
	results, err := store.Query(ctx, api.QueryFilter{Verdict: api.VerdictDeny})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 deny result, got %d", len(results))
	}

	// Filter by tool
	results, err = store.Query(ctx, api.QueryFilter{Tool: "read_file"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 read_file result, got %d", len(results))
	}

	// Filter with limit
	results, err = store.Query(ctx, api.QueryFilter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results with limit, got %d", len(results))
	}
}

func TestJSONLStore_Stats(t *testing.T) {
	dir := t.TempDir()
	store, err := NewJSONLStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()

	records := []*api.AuditRecord{
		{Timestamp: time.Now(), Method: "tools/call", Tool: "read_file", Verdict: api.VerdictAllow},
		{Timestamp: time.Now(), Method: "tools/call", Tool: "write_file", Verdict: api.VerdictDeny},
		{Timestamp: time.Now(), Method: "initialize", Verdict: api.VerdictAllow},
		{Timestamp: time.Now(), Method: "tools/call", Tool: "read_file", Verdict: api.VerdictAllow},
	}
	for _, r := range records {
		if err := store.Write(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	stats, err := store.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.TotalRequests != 4 {
		t.Errorf("expected 4 total, got %d", stats.TotalRequests)
	}
	if stats.AllowCount != 3 {
		t.Errorf("expected 3 allows, got %d", stats.AllowCount)
	}
	if stats.DenyCount != 1 {
		t.Errorf("expected 1 deny, got %d", stats.DenyCount)
	}
	if stats.ByTool["read_file"] != 2 {
		t.Errorf("expected 2 read_file calls, got %d", stats.ByTool["read_file"])
	}
}

func TestJSONLStore_FileCreation(t *testing.T) {
	dir := t.TempDir()
	store, err := NewJSONLStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	record := &api.AuditRecord{
		Timestamp: now,
		Method:    "test",
		Verdict:   api.VerdictAllow,
	}
	if err := store.Write(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	store.Close()

	expectedFile := filepath.Join(dir, now.Format("2006-01-02")+".jsonl")
	if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
		t.Errorf("expected audit log file %s to exist", expectedFile)
	}
}

func TestJSONLStore_Subscribe(t *testing.T) {
	dir := t.TempDir()
	store, err := NewJSONLStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ch, cancel := store.Subscribe(context.Background())
	defer cancel()

	go func() {
		record := &api.AuditRecord{
			Timestamp: time.Now(),
			Method:    "test",
			Verdict:   api.VerdictAllow,
		}
		store.Write(context.Background(), record)
	}()

	select {
	case r := <-ch:
		if r.Method != "test" {
			t.Errorf("expected method test, got %s", r.Method)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for subscription event")
	}
}
