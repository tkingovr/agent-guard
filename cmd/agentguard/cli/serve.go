package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/tkingovr/agent-guard/internal/approval"
	"github.com/tkingovr/agent-guard/internal/audit"
	"github.com/tkingovr/agent-guard/internal/config"
	"github.com/tkingovr/agent-guard/internal/dashboard"
	"github.com/tkingovr/agent-guard/internal/filter"
	"github.com/tkingovr/agent-guard/internal/policy"
	stdioproxy "github.com/tkingovr/agent-guard/internal/proxy/stdio"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve [flags] -- <command> [args...]",
	Short: "Start the stdio proxy + web dashboard",
	Long: `Start both the stdio MCP proxy and the web dashboard together.
This is the recommended way to run AgentGuard.`,
	Example: `  agentguard serve -c policy.yaml -- npx @modelcontextprotocol/server-filesystem ~/projects`,
	Args:    cobra.MinimumNArgs(1),
	RunE:    runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
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

	var engine *policy.YAMLEngine
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

	auditStore, err := audit.NewJSONLStore(cfg.LogDir)
	if err != nil {
		return fmt.Errorf("creating audit store: %w", err)
	}
	defer auditStore.Close()

	aq := approval.NewQueue(cfg.ApprovalTimeout)

	// Build filter chains
	chainCfg := filter.ChainConfig{
		Engine:           engine,
		AuditStore:       auditStore,
		Logger:           logger,
		SecretScanner:    cfg.SecretScanner,
		EntropyThreshold: cfg.EntropyThreshold,
		RateLimit:        filter.RateLimitConfigFromPolicy(cfg.RateLimit),
	}
	inbound := filter.BuildInboundChain(chainCfg)
	outbound := filter.BuildOutboundChain(chainCfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("shutting down")
		cancel()
	}()

	// Start dashboard in background
	dash := dashboard.NewServer(cfg.DashboardAddr, auditStore, aq, engine, logger)
	go func() {
		if err := dash.ListenAndServe(ctx); err != nil {
			logger.Error("dashboard error", "error", err)
		}
	}()

	logger.Info("starting serve mode",
		slog.String("command", args[0]),
		slog.String("dashboard", cfg.DashboardAddr),
	)

	// Start proxy (blocks)
	proxy := stdioproxy.NewProxy(logger, inbound, outbound, aq)
	return proxy.Run(ctx, args[0], args[1:])
}
