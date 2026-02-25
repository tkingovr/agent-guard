package stdio

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/aqubia/agent-guard/api"
	"github.com/aqubia/agent-guard/internal/approval"
	"github.com/aqubia/agent-guard/internal/filter"
	"github.com/aqubia/agent-guard/internal/jsonrpc"
)

// Proxy is the stdio MITM proxy that sits between the AI host and the real MCP server.
type Proxy struct {
	logger        *slog.Logger
	inboundChain  *filter.Chain
	outboundChain *filter.Chain
	approvalQueue *approval.Queue
}

// NewProxy creates a new stdio proxy with the given filter chains.
func NewProxy(logger *slog.Logger, inbound, outbound *filter.Chain, aq *approval.Queue) *Proxy {
	return &Proxy{
		logger:        logger,
		inboundChain:  inbound,
		outboundChain: outbound,
		approvalQueue: aq,
	}
}

// Run starts the proxy, spawning the subprocess and bridging stdin/stdout.
func (p *Proxy) Run(ctx context.Context, command string, args []string) error {
	proc, err := StartProcess(command, args)
	if err != nil {
		return err
	}
	defer func() {
		_ = proc.Kill()
	}()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)

	// Inbound: our stdin → filter chain → subprocess stdin
	go func() {
		errCh <- p.pipeInbound(ctx, os.Stdin, proc.Stdin())
	}()

	// Outbound: subprocess stdout → filter chain → our stdout
	go func() {
		errCh <- p.pipeOutbound(ctx, proc.Stdout(), os.Stdout)
	}()

	// Wait for either pipe to end or subprocess to exit
	select {
	case err := <-errCh:
		cancel()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *Proxy) pipeInbound(ctx context.Context, src io.Reader, dst io.WriteCloser) error {
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024) // 10MB max message

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		fc := filter.NewFilterContext(line, api.DirectionInbound)
		if err := p.inboundChain.Process(ctx, fc); err != nil {
			p.logger.Error("inbound filter error", "error", err)
			continue
		}

		switch fc.Verdict {
		case api.VerdictDeny:
			p.logger.Warn("request denied",
				"method", fc.Method,
				"tool", fc.Tool,
				"rule", fc.MatchedRule,
				"message", fc.VerdictMessage,
			)
			// Send error response back to client
			if fc.Message != nil && fc.Message.ID != nil {
				errResp := jsonrpc.NewDenyResponse(fc.Message.ID, fc.VerdictMessage)
				if err := writeLine(os.Stdout, errResp); err != nil {
					return fmt.Errorf("writing deny response: %w", err)
				}
			}
			continue

		case api.VerdictAsk:
			p.logger.Info("request pending approval",
				"method", fc.Method,
				"tool", fc.Tool,
				"rule", fc.MatchedRule,
			)
			if p.approvalQueue != nil {
				verdict, err := p.approvalQueue.Submit(ctx, fc.Method, fc.Tool, fc.MatchedRule, fc.VerdictMessage, fc.Arguments)
				if err != nil || verdict == api.VerdictDeny {
					msg := "request denied by approver"
					if err != nil {
						msg = "approval error: " + err.Error()
					}
					if fc.Message != nil && fc.Message.ID != nil {
						errResp := jsonrpc.NewDenyResponse(fc.Message.ID, msg)
						if err := writeLine(os.Stdout, errResp); err != nil {
							return fmt.Errorf("writing deny response: %w", err)
						}
					}
					continue
				}
			}
		}

		// Forward allowed/logged messages to subprocess
		if _, err := dst.Write(line); err != nil {
			return fmt.Errorf("writing to subprocess: %w", err)
		}
		if _, err := dst.Write([]byte("\n")); err != nil {
			return fmt.Errorf("writing newline to subprocess: %w", err)
		}
	}

	return scanner.Err()
}

func (p *Proxy) pipeOutbound(ctx context.Context, src io.Reader, dst io.Writer) error {
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		if p.outboundChain != nil {
			fc := filter.NewFilterContext(line, api.DirectionOutbound)
			if err := p.outboundChain.Process(ctx, fc); err != nil {
				p.logger.Error("outbound filter error", "error", err)
			}
		}

		// Always forward outbound (responses from server)
		if _, err := dst.Write(line); err != nil {
			return fmt.Errorf("writing to stdout: %w", err)
		}
		if _, err := dst.Write([]byte("\n")); err != nil {
			return fmt.Errorf("writing newline to stdout: %w", err)
		}
	}

	return scanner.Err()
}

func writeLine(w io.Writer, msg *api.JSONRPCMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	_, err = w.Write([]byte("\n"))
	return err
}
