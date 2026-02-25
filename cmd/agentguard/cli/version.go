package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is set by goreleaser via ldflags
var version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of AgentGuard",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("agentguard %s\n", version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
