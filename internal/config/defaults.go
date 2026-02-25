package config

import "time"

const (
	DefaultDashboardAddr   = "127.0.0.1:8080"
	DefaultApprovalTimeout = 5 * time.Minute
)

// DefaultLogDir returns the default log directory path.
func DefaultLogDir() string {
	return "~/.agentguard/logs"
}
