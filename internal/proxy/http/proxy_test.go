package http

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tkingovr/agent-guard/api"
	"github.com/tkingovr/agent-guard/internal/audit"
	"github.com/tkingovr/agent-guard/internal/filter"
	"github.com/tkingovr/agent-guard/internal/policy"
)

func TestHTTPProxy_AllowedRequest(t *testing.T) {
	// Create a mock MCP server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05"}}`))
	}))
	defer backend.Close()

	// Create policy engine
	pf := &policy.PolicyFile{
		Version:  1,
		Settings: policy.Settings{DefaultAction: api.VerdictDeny},
		Rules: []policy.Rule{
			{Name: "allow-init", Match: policy.RuleMatch{Method: "initialize"}, Action: "allow"},
		},
	}
	engine, _ := policy.NewYAMLEngineFromPolicy(pf)

	dir := t.TempDir()
	store, _ := audit.NewJSONLStore(dir)
	defer store.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	chain := filter.NewChain(logger,
		filter.NewParseFilter(),
		filter.NewPolicyFilter(engine),
		filter.NewAuditFilter(store),
	)

	proxy, err := NewProxy(backend.URL, chain, logger)
	if err != nil {
		t.Fatal(err)
	}

	// Send allowed request
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "protocolVersion") {
		t.Error("expected proxied response to contain protocolVersion")
	}
}

func TestHTTPProxy_DeniedRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("backend should not be called for denied requests")
	}))
	defer backend.Close()

	pf := &policy.PolicyFile{
		Version:  1,
		Settings: policy.Settings{DefaultAction: api.VerdictDeny},
		Rules:    []policy.Rule{},
	}
	engine, _ := policy.NewYAMLEngineFromPolicy(pf)

	dir := t.TempDir()
	store, _ := audit.NewJSONLStore(dir)
	defer store.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	chain := filter.NewChain(logger,
		filter.NewParseFilter(),
		filter.NewPolicyFilter(engine),
		filter.NewAuditFilter(store),
	)

	proxy, _ := NewProxy(backend.URL, chain, logger)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dangerous_tool"}}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (JSON-RPC error in body), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "error") {
		t.Error("expected deny error in response body")
	}
}

func TestHTTPProxy_GETPassthrough(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	chain := filter.NewChain(logger)
	proxy, _ := NewProxy(backend.URL, chain, logger)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for GET passthrough, got %d", w.Code)
	}
}
