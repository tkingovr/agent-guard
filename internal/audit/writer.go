package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tkingovr/agent-guard/api"
)

// JSONLStore is an append-only JSONL file audit store with date-based rotation.
type JSONLStore struct {
	mu          sync.Mutex
	dir         string
	currentDate string
	file        *os.File
	writer      *bufio.Writer

	// In-memory buffer for queries and stats (bounded)
	records []*api.AuditRecord
	maxMem  int

	// Subscribers for real-time streaming
	subMu   sync.RWMutex
	subs    map[int]chan *api.AuditRecord
	nextSub int
}

// NewJSONLStore creates a new JSONL audit store writing to the given directory.
func NewJSONLStore(dir string) (*JSONLStore, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("creating audit log directory: %w", err)
	}
	s := &JSONLStore{
		dir:    dir,
		maxMem: 10000,
		subs:   make(map[int]chan *api.AuditRecord),
	}
	return s, nil
}

func (s *JSONLStore) Write(_ context.Context, record *api.AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate ID if empty
	if record.ID == "" {
		record.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	if record.Timestamp.IsZero() {
		record.Timestamp = time.Now()
	}

	// Rotate file if date changed
	dateStr := record.Timestamp.Format("2006-01-02")
	if dateStr != s.currentDate {
		if err := s.rotate(dateStr); err != nil {
			return err
		}
	}

	// Write JSONL line
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshaling audit record: %w", err)
	}
	if _, err := s.writer.Write(data); err != nil {
		return err
	}
	if err := s.writer.WriteByte('\n'); err != nil {
		return err
	}
	if err := s.writer.Flush(); err != nil {
		return err
	}

	// Keep in memory (bounded)
	if len(s.records) >= s.maxMem {
		s.records = s.records[1:]
	}
	s.records = append(s.records, record)

	// Notify subscribers
	s.notifySubscribers(record)

	return nil
}

func (s *JSONLStore) Query(_ context.Context, filter api.QueryFilter) ([]*api.AuditRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var results []*api.AuditRecord
	for _, r := range s.records {
		if matchesFilter(r, filter) {
			results = append(results, r)
		}
	}

	// Apply offset and limit
	if filter.Offset > 0 {
		if filter.Offset >= len(results) {
			return nil, nil
		}
		results = results[filter.Offset:]
	}
	if filter.Limit > 0 && len(results) > filter.Limit {
		results = results[:filter.Limit]
	}

	return results, nil
}

func (s *JSONLStore) Stats(_ context.Context) (*api.AuditStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats := &api.AuditStats{
		ByMethod: make(map[string]int),
		ByTool:   make(map[string]int),
	}

	for _, r := range s.records {
		stats.TotalRequests++
		switch r.Verdict {
		case api.VerdictAllow:
			stats.AllowCount++
		case api.VerdictDeny:
			stats.DenyCount++
		case api.VerdictAsk:
			stats.AskCount++
		case api.VerdictLog:
			stats.LogCount++
		}
		if r.Method != "" {
			stats.ByMethod[r.Method]++
		}
		if r.Tool != "" {
			stats.ByTool[r.Tool]++
		}
	}

	return stats, nil
}

func (s *JSONLStore) Subscribe(_ context.Context) (<-chan *api.AuditRecord, func()) {
	s.subMu.Lock()
	defer s.subMu.Unlock()

	ch := make(chan *api.AuditRecord, 100)
	id := s.nextSub
	s.nextSub++
	s.subs[id] = ch

	cancel := func() {
		s.subMu.Lock()
		defer s.subMu.Unlock()
		delete(s.subs, id)
		close(ch)
	}

	return ch, cancel
}

func (s *JSONLStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.writer != nil {
		if err := s.writer.Flush(); err != nil {
			return err
		}
	}
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

func (s *JSONLStore) rotate(dateStr string) error {
	if s.writer != nil {
		if err := s.writer.Flush(); err != nil {
			return err
		}
	}
	if s.file != nil {
		if err := s.file.Close(); err != nil {
			return err
		}
	}

	path := filepath.Join(s.dir, dateStr+".jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("opening audit log file: %w", err)
	}

	s.file = f
	s.writer = bufio.NewWriter(f)
	s.currentDate = dateStr
	return nil
}

func (s *JSONLStore) notifySubscribers(record *api.AuditRecord) {
	s.subMu.RLock()
	defer s.subMu.RUnlock()

	for _, ch := range s.subs {
		select {
		case ch <- record:
		default:
			// Drop if subscriber is slow
		}
	}
}

func matchesFilter(r *api.AuditRecord, f api.QueryFilter) bool {
	if !f.Since.IsZero() && r.Timestamp.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && r.Timestamp.After(f.Until) {
		return false
	}
	if f.Method != "" && r.Method != f.Method {
		return false
	}
	if f.Tool != "" && r.Tool != f.Tool {
		return false
	}
	if f.Verdict != "" && r.Verdict != f.Verdict {
		return false
	}
	return true
}
