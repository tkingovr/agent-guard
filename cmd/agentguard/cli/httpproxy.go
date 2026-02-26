package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/tkingovr/agent-guard/internal/audit"
	"github.com/tkingovr/agent-guard/internal/config"
	"github.com/tkingovr/agent-guard/internal/filter"
	"github.com/tkingovr/agent-guard/internal/policy"
	httpproxy "github.com/tkingovr/agent-guard/internal/proxy/http"
	"github.com/spf13/cobra"
)

var (
	httpTarget string
	httpListen string
)

var httpproxyCmd = &cobra.Command{
	Use:   "httpproxy",
	Short: "Start the HTTP Streamable MCP proxy",
	Long: `Start an HTTP reverse proxy that intercepts MCP JSON-RPC messages
sent over HTTP Streamable transport.`,
	Example: `  agentguard httpproxy -c policy.yaml --target http://localhost:4000/mcp --listen :3000`,
	RunE:    runHTTPProxy,
}

func init() {
	httpproxyCmd.Flags().StringVar(&httpTarget, "target", "", "target MCP server URL (required)")
	httpproxyCmd.Flags().StringVar(&httpListen, "listen", ":3000", "listen address")
	_ = httpproxyCmd.MarkFlagRequired("target")
	rootCmd.AddCommand(httpproxyCmd)
}

func runHTTPProxy(cmd *cobra.Command, args []string) error {
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

	auditStore, err := audit.NewJSONLStore(cfg.LogDir)
	if err != nil {
		return fmt.Errorf("creating audit store: %w", err)
	}
	defer auditStore.Close()

	chain := filter.NewChain(logger,
		filter.NewParseFilter(),
		filter.NewPolicyFilter(engine),
		filter.NewAuditFilter(auditStore),
	)

	proxy, err := httpproxy.NewProxy(httpTarget, chain, logger)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("shutting down HTTP proxy")
		cancel()
	}()

	return proxy.ListenAndServe(ctx, httpListen)
}
