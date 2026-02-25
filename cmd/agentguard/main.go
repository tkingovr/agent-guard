package main

import (
	"os"

	"github.com/aqubia/agent-guard/cmd/agentguard/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
