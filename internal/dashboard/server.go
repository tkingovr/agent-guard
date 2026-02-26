package dashboard

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/tkingovr/agent-guard/internal/approval"
	"github.com/tkingovr/agent-guard/internal/audit"
	"github.com/tkingovr/agent-guard/internal/policy"
)

// Server is the web dashboard HTTP server.
type Server struct {
	mux        *http.ServeMux
	logger     *slog.Logger
	auditStore audit.Store
	approvalQ  *approval.Queue
	engine     *policy.YAMLEngine
	addr       string
}

// NewServer creates a new dashboard server.
func NewServer(addr string, store audit.Store, aq *approval.Queue, engine *policy.YAMLEngine, logger *slog.Logger) *Server {
	s := &Server{
		mux:        http.NewServeMux(),
		logger:     logger,
		auditStore: store,
		approvalQ:  aq,
		engine:     engine,
		addr:       addr,
	}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /", s.handleOverview)
	s.mux.HandleFunc("GET /audit", s.handleAudit)
	s.mux.HandleFunc("GET /audit/stream", s.handleAuditStream)
	s.mux.HandleFunc("GET /approval", s.handleApproval)
	s.mux.HandleFunc("POST /approval/{id}/approve", s.handleApprovalAction)
	s.mux.HandleFunc("POST /approval/{id}/deny", s.handleApprovalDenyAction)
	s.mux.HandleFunc("GET /policy", s.handlePolicy)
	s.mux.HandleFunc("GET /api/v1/stats", s.handleAPIStats)
	s.mux.HandleFunc("POST /api/v1/check", s.handleAPICheck)
}

// ListenAndServe starts the dashboard HTTP server.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:    s.addr,
		Handler: s.mux,
	}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	s.logger.Info("starting dashboard", "addr", s.addr)
	return srv.ListenAndServe()
}

// Handler returns the HTTP handler for embedding in other servers.
func (s *Server) Handler() http.Handler {
	return s.mux
}
