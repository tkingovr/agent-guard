package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/tkingovr/agent-guard/api"
	"github.com/tkingovr/agent-guard/internal/filter"
	"github.com/tkingovr/agent-guard/internal/jsonrpc"
)

// Proxy is an HTTP reverse proxy for MCP Streamable HTTP transport.
type Proxy struct {
	target       *url.URL
	reverseProxy *httputil.ReverseProxy
	filterChain  *filter.Chain
	logger       *slog.Logger
}

// NewProxy creates a new HTTP MCP proxy targeting the given URL.
func NewProxy(target string, chain *filter.Chain, logger *slog.Logger) (*Proxy, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	p := &Proxy{
		target:      u,
		filterChain: chain,
		logger:      logger,
	}

	rp := httputil.NewSingleHostReverseProxy(u)
	rp.Director = p.director
	rp.ModifyResponse = p.modifyResponse
	rp.ErrorHandler = p.errorHandler
	p.reverseProxy = rp

	return p, nil
}

// ServeHTTP handles incoming HTTP requests.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only intercept POST requests (MCP JSON-RPC over HTTP)
	if r.Method != http.MethodPost {
		p.reverseProxy.ServeHTTP(w, r)
		return
	}

	// Read the request body
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		p.logger.Error("reading request body", "error", err)
		http.Error(w, "failed to read request", http.StatusBadRequest)
		return
	}

	// Run through filter chain
	fc := filter.NewFilterContext(body, api.DirectionInbound)
	if err := p.filterChain.Process(r.Context(), fc); err != nil {
		p.logger.Error("filter chain error", "error", err)
		http.Error(w, "internal filter error", http.StatusInternalServerError)
		return
	}

	switch fc.Verdict {
	case api.VerdictDeny:
		p.logger.Warn("request denied",
			"method", fc.Method,
			"tool", fc.Tool,
			"rule", fc.MatchedRule,
		)
		p.writeDenyResponse(w, fc)
		return

	case api.VerdictAsk:
		p.logger.Info("request pending approval",
			"method", fc.Method,
			"tool", fc.Tool,
		)
		// For now, deny with a message suggesting approval via dashboard
		p.writeDenyResponse(w, fc)
		return
	}

	// Forward allowed request
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	p.reverseProxy.ServeHTTP(w, r)
}

func (p *Proxy) director(req *http.Request) {
	req.URL.Scheme = p.target.Scheme
	req.URL.Host = p.target.Host
	req.URL.Path = p.target.Path
	req.Host = p.target.Host
}

func (p *Proxy) modifyResponse(resp *http.Response) error {
	// Log outbound responses
	if resp.Header.Get("Content-Type") == "text/event-stream" {
		// SSE responses are streamed, log at connection level
		p.logger.Debug("SSE response stream opened", "status", resp.StatusCode)
		return nil
	}
	return nil
}

func (p *Proxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	p.logger.Error("proxy error", "error", err, "url", r.URL.String())
	http.Error(w, "proxy error: "+err.Error(), http.StatusBadGateway)
}

func (p *Proxy) writeDenyResponse(w http.ResponseWriter, fc *filter.FilterContext) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // JSON-RPC errors use 200 status

	var id json.RawMessage
	if fc.Message != nil && fc.Message.ID != nil {
		id = fc.Message.ID
	}

	msg := fc.VerdictMessage
	if msg == "" {
		msg = "request denied by policy"
	}

	resp := jsonrpc.NewDenyResponse(id, msg)
	data, _ := json.Marshal(resp)
	w.Write(data)
}

// Handler returns an http.Handler for use with http.Server.
func (p *Proxy) Handler() http.Handler {
	return p
}

// ListenAndServe starts the HTTP proxy server.
func (p *Proxy) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: p,
	}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	p.logger.Info("starting HTTP proxy",
		"listen", addr,
		"target", p.target.String(),
	)

	return srv.ListenAndServe()
}
