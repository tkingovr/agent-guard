package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/aqubia/agent-guard/internal/config"
	"github.com/aqubia/agent-guard/internal/policy"
	"github.com/spf13/cobra"
)

var (
	checkMethod string
	checkTool   string
	checkArgs   string
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Dry-run a policy check without a running proxy",
	Long: `Check what verdict a request would receive without running the proxy.
Useful for testing and debugging policy rules.`,
	Example: `  agentguard check -c policy.yaml --method tools/call --tool read_file --args '{"path":"/etc/passwd"}'
  agentguard check -c policy.yaml --method initialize`,
	RunE: runCheck,
}

func init() {
	checkCmd.Flags().StringVar(&checkMethod, "method", "", "JSON-RPC method to check")
	checkCmd.Flags().StringVar(&checkTool, "tool", "", "tool name (for tools/call)")
	checkCmd.Flags().StringVar(&checkArgs, "args", "", "JSON arguments")
	_ = checkCmd.MarkFlagRequired("method")
	rootCmd.AddCommand(checkCmd)
}

func runCheck(cmd *cobra.Command, args []string) error {
	if cfgFile == "" {
		return fmt.Errorf("--config/-c is required for check command")
	}

	_, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	engine, err := policy.NewYAMLEngine(cfgFile)
	if err != nil {
		return fmt.Errorf("creating policy engine: %w", err)
	}

	input := &policy.EvalInput{
		Method: checkMethod,
		Tool:   checkTool,
	}

	if checkArgs != "" {
		input.Arguments = json.RawMessage(checkArgs)
	}

	result, err := engine.Evaluate(context.Background(), input)
	if err != nil {
		return fmt.Errorf("evaluation error: %w", err)
	}

	output := struct {
		Verdict string `json:"verdict"`
		Rule    string `json:"rule"`
		Message string `json:"message,omitempty"`
	}{
		Verdict: string(result.Verdict),
		Rule:    result.Rule,
		Message: result.Message,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}
