package cli

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile string
	verbose bool
	logger  *slog.Logger
)

var rootCmd = &cobra.Command{
	Use:   "agentguard",
	Short: "AgentGuard — AI agent firewall and audit layer",
	Long: `AgentGuard is an open-source firewall and audit layer for AI agents.
It intercepts MCP (Model Context Protocol) tool calls, evaluates them
against configurable policies, and provides real-time audit logging
with a web dashboard.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		level := slog.LevelInfo
		if verbose {
			level = slog.LevelDebug
		}
		logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: level,
		}))
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "policy config file (YAML)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable debug logging")
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
