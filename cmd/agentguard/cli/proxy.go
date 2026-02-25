package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/aqubia/agent-guard/internal/approval"
	"github.com/aqubia/agent-guard/internal/audit"
	"github.com/aqubia/agent-guard/internal/config"
	"github.com/aqubia/agent-guard/internal/filter"
	"github.com/aqubia/agent-guard/internal/policy"
	stdioproxy "github.com/aqubia/agent-guard/internal/proxy/stdio"
	"github.com/spf13/cobra"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy [flags] -- <command> [args...]",
	Short: "Start the stdio MCP proxy",
	Long: `Start a stdio MCP proxy that intercepts JSON-RPC messages between
the AI host and the real MCP server subprocess.

The command after -- is the real MCP server to spawn.`,
	Example: `  agentguard proxy -c policy.yaml -- npx @modelcontextprotocol/server-filesystem ~/projects
  agentguard proxy -c configs/default.yaml -- python mcp_server.py`,
	Args: cobra.MinimumNArgs(1),
	RunE: runProxy,
}

func init() {
	rootCmd.AddCommand(proxyCmd)
}

func runProxy(cmd *cobra.Command, args []string) error {
	// Load config
	var cfg *config.Config
	var err error
	if cfgFile != "" {
		cfg, err = config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
	} else {
		cfg = config.DefaultConfig()
	}

	// Create policy engine
	var engine policy.Engine
	if cfgFile != "" {
		engine, err = policy.NewYAMLEngine(cfgFile)
		if err != nil {
			return fmt.Errorf("creating policy engine: %w", err)
		}
	} else {
		engine, err = policy.NewYAMLEngineFromPolicy(cfg.PolicyFile)
		if err != nil {
			return fmt.Errorf("creating policy engine: %w", err)
		}
	}

	// Create audit store
	auditStore, err := audit.NewJSONLStore(cfg.LogDir)
	if err != nil {
		return fmt.Errorf("creating audit store: %w", err)
	}
	defer auditStore.Close()

	// Create approval queue
	aq := approval.NewQueue(cfg.ApprovalTimeout)

	// Build inbound filter chain
	inbound := filter.NewChain(logger,
		filter.NewParseFilter(),
		filter.NewPolicyFilter(engine),
		filter.NewAuditFilter(auditStore),
	)

	// Build outbound filter chain (parse + audit only)
	outbound := filter.NewChain(logger,
		filter.NewOutboundParseFilter(),
		filter.NewAuditFilter(auditStore),
	)

	// Create and run proxy
	proxy := stdioproxy.NewProxy(logger, inbound, outbound, aq)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("shutting down proxy")
		cancel()
	}()

	logger.Info("starting stdio proxy",
		slog.String("command", args[0]),
		slog.Any("args", args[1:]),
		slog.String("policy", cfgFile),
	)

	return proxy.Run(ctx, args[0], args[1:])
}
