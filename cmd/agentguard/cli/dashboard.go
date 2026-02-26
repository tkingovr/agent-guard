package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/tkingovr/agent-guard/internal/approval"
	"github.com/tkingovr/agent-guard/internal/audit"
	"github.com/tkingovr/agent-guard/internal/config"
	"github.com/tkingovr/agent-guard/internal/dashboard"
	"github.com/tkingovr/agent-guard/internal/policy"
	"github.com/spf13/cobra"
)

var (
	dashAddr   string
	dashLogDir string
)

var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Start the web dashboard only (no proxy)",
	Long: `Start the web dashboard for viewing audit logs, managing approvals,
and viewing policy rules. Reads from existing audit log files.`,
	Example: `  agentguard dashboard -l :8080 -a ~/.agentguard/logs
  agentguard dashboard -c policy.yaml`,
	RunE: runDashboard,
}

func init() {
	dashboardCmd.Flags().StringVarP(&dashAddr, "listen", "l", "127.0.0.1:8080", "dashboard listen address")
	dashboardCmd.Flags().StringVarP(&dashLogDir, "audit-dir", "a", "", "audit log directory")
	rootCmd.AddCommand(dashboardCmd)
}

func runDashboard(cmd *cobra.Command, args []string) error {
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

	if dashAddr != "" {
		cfg.DashboardAddr = dashAddr
	}
	if dashLogDir != "" {
		cfg.LogDir = dashLogDir
	}

	auditStore, err := audit.NewJSONLStore(cfg.LogDir)
	if err != nil {
		return fmt.Errorf("creating audit store: %w", err)
	}
	defer auditStore.Close()

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

	aq := approval.NewQueue(cfg.ApprovalTimeout)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("shutting down dashboard")
		cancel()
	}()

	dash := dashboard.NewServer(cfg.DashboardAddr, auditStore, aq, engine, logger)
	return dash.ListenAndServe(ctx)
}
