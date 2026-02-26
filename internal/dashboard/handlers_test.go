package dashboard

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tkingovr/agent-guard/api"
	"github.com/tkingovr/agent-guard/internal/approval"
	"github.com/tkingovr/agent-guard/internal/audit"
	"github.com/tkingovr/agent-guard/internal/policy"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	store, err := audit.NewJSONLStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	pf := &policy.PolicyFile{
		Version: 1,
		Settings: policy.Settings{
			DefaultAction: api.VerdictDeny,
		},
		Rules: []policy.Rule{
			{Name: "allow-init", Match: policy.RuleMatch{Method: "initialize"}, Action: "allow"},
		},
	}
	engine, err := policy.NewYAMLEngineFromPolicy(pf)
	if err != nil {
		t.Fatal(err)
	}

	aq := approval.NewQueue(5 * time.Minute)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	return NewServer(":0", store, aq, engine, logger)
}

func TestOverviewPage(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "AgentGuard") {
		t.Error("expected page to contain 'AgentGuard'")
	}
}

func TestAuditPage(t *testing.T) {
	s := testServer(t)

	// Write some audit records
	s.auditStore.Write(context.Background(), &api.AuditRecord{
		Timestamp: time.Now(),
		Method:    "tools/call",
		Tool:      "read_file",
		Verdict:   api.VerdictAllow,
		Rule:      "allow-read",
	})

	req := httptest.NewRequest("GET", "/audit", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Audit Log") {
		t.Error("expected page to contain 'Audit Log'")
	}
}

func TestApprovalPage(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest("GET", "/approval", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestPolicyPage(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest("GET", "/policy", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Active Policy") {
		t.Error("expected page to contain 'Active Policy'")
	}
}

func TestAPIStats(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var stats api.AuditStats
	if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}
}

func TestAPICheck(t *testing.T) {
	s := testServer(t)

	body := `{"method":"initialize"}`
	req := httptest.NewRequest("POST", "/api/v1/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp api.CheckResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != api.VerdictAllow {
		t.Errorf("expected allow, got %s", resp.Verdict)
	}
}

func TestAPICheck_Deny(t *testing.T) {
	s := testServer(t)

	body := `{"method":"unknown/method"}`
	req := httptest.NewRequest("POST", "/api/v1/check", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	var resp api.CheckResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Verdict != api.VerdictDeny {
		t.Errorf("expected deny, got %s", resp.Verdict)
	}
}
