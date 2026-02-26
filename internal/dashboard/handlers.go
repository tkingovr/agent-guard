package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/tkingovr/agent-guard/api"
	"github.com/tkingovr/agent-guard/internal/policy"
	"gopkg.in/yaml.v3"
)

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	stats, err := s.auditStore.Stats(r.Context())
	if err != nil {
		http.Error(w, "failed to get stats", http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"Page":  "overview",
		"Stats": stats,
	}
	renderPage(w, "overview", data)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	records, err := s.auditStore.Query(r.Context(), api.QueryFilter{Limit: 100})
	if err != nil {
		http.Error(w, "failed to query audit log", http.StatusInternalServerError)
		return
	}

	// Reverse to show newest first
	for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
		records[i], records[j] = records[j], records[i]
	}

	data := map[string]any{
		"Page":    "audit",
		"Records": records,
	}
	renderPage(w, "audit", data)
}

func (s *Server) handleAuditStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	ch, cancel := s.auditStore.Subscribe(r.Context())
	defer cancel()

	for {
		select {
		case record, ok := <-ch:
			if !ok {
				return
			}
			html := renderAuditRow(record)
			fmt.Fprintf(w, "event: audit\ndata: %s\n\n", html)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) handleApproval(w http.ResponseWriter, r *http.Request) {
	pending := s.approvalQ.Pending()
	all := s.approvalQ.All()

	data := map[string]any{
		"Page":    "approval",
		"Pending": pending,
		"All":     all,
	}
	renderPage(w, "approval", data)
}

func (s *Server) handleApprovalAction(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.approvalQ.Approve(id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// HTMX: return updated approval list
	s.handleApproval(w, r)
}

func (s *Server) handleApprovalDenyAction(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.approvalQ.Deny(id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.handleApproval(w, r)
}

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	pf := s.engine.Policy()
	policyYAML, _ := yaml.Marshal(pf)

	data := map[string]any{
		"Page":       "policy",
		"PolicyYAML": string(policyYAML),
		"Policy":     pf,
	}
	renderPage(w, "policy", data)
}

func (s *Server) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.auditStore.Stats(r.Context())
	if err != nil {
		http.Error(w, "failed to get stats", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleAPICheck(w http.ResponseWriter, r *http.Request) {
	var req api.CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	input := &policy.EvalInput{
		Method:    req.Method,
		Tool:      req.Tool,
		Arguments: req.Arguments,
	}

	result, err := s.engine.Evaluate(context.Background(), input)
	if err != nil {
		http.Error(w, "evaluation error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := api.CheckResponse{
		Verdict: result.Verdict,
		Rule:    result.Rule,
		Message: result.Message,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func renderAuditRow(record *api.AuditRecord) string {
	verdictClass := verdictColor(record.Verdict)
	args := ""
	if record.Arguments != nil {
		args = truncate(string(record.Arguments), 80)
	}

	return fmt.Sprintf(
		`<tr class="border-b border-gray-700 hover:bg-gray-800"><td class="px-4 py-2 text-gray-400 text-xs">%s</td><td class="px-4 py-2">%s</td><td class="px-4 py-2">%s</td><td class="px-4 py-2 font-mono text-sm">%s</td><td class="px-4 py-2"><span class="px-2 py-1 rounded text-xs font-bold %s">%s</span></td><td class="px-4 py-2 text-gray-400 text-xs">%s</td></tr>`,
		record.Timestamp.Format(time.RFC3339),
		escapeHTML(record.Method),
		escapeHTML(record.Tool),
		escapeHTML(args),
		verdictClass,
		strings.ToUpper(string(record.Verdict)),
		escapeHTML(record.Rule),
	)
}

func verdictColor(v api.Verdict) string {
	switch v {
	case api.VerdictAllow:
		return "bg-green-900 text-green-300"
	case api.VerdictDeny:
		return "bg-red-900 text-red-300"
	case api.VerdictAsk:
		return "bg-yellow-900 text-yellow-300"
	case api.VerdictLog:
		return "bg-blue-900 text-blue-300"
	default:
		return "bg-gray-700 text-gray-300"
	}
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func escapeHTML(s string) string {
	return template.HTMLEscapeString(s)
}
