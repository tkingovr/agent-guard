package main

import (
	"os"

	"github.com/tkingovr/agent-guard/cmd/agentguard/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
