package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tkingovr/agent-guard/api"
	"github.com/tkingovr/agent-guard/internal/policy"
	"gopkg.in/yaml.v3"
)

// Config is the runtime configuration for AgentGuard.
type Config struct {
	PolicyFile      *policy.PolicyFile
	PolicyPath      string
	LogDir          string
	DashboardAddr   string
	ApprovalTimeout time.Duration
	DefaultAction   api.Verdict
}

// Load reads a policy YAML file and produces a runtime Config.
func Load(path string) (*Config, error) {
	pf, err := policy.LoadFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	return fromPolicy(pf, path)
}

// LoadBytes parses YAML data and produces a runtime Config.
func LoadBytes(data []byte) (*Config, error) {
	pf, err := policy.LoadBytes(data)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	return fromPolicy(pf, "")
}

func fromPolicy(pf *policy.PolicyFile, path string) (*Config, error) {
	cfg := &Config{
		PolicyFile:    pf,
		PolicyPath:    path,
		DefaultAction: pf.Settings.DefaultAction,
	}

	// Log directory
	cfg.LogDir = pf.Settings.LogDir
	if cfg.LogDir == "" {
		cfg.LogDir = DefaultLogDir()
	}
	cfg.LogDir = expandHome(cfg.LogDir)

	// Dashboard address
	cfg.DashboardAddr = pf.Settings.DashboardAddr
	if cfg.DashboardAddr == "" {
		cfg.DashboardAddr = DefaultDashboardAddr
	}

	// Approval timeout
	if pf.Settings.ApprovalTimeout != "" {
		d, err := time.ParseDuration(pf.Settings.ApprovalTimeout)
		if err != nil {
			return nil, fmt.Errorf("invalid approval_timeout %q: %w", pf.Settings.ApprovalTimeout, err)
		}
		cfg.ApprovalTimeout = d
	} else {
		cfg.ApprovalTimeout = DefaultApprovalTimeout
	}

	return cfg, nil
}

func expandHome(path string) string {
	if len(path) > 1 && path[0] == '~' && path[1] == '/' {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[2:])
	}
	return path
}

// DefaultConfig returns a config with defaults for when no config file is given.
func DefaultConfig() *Config {
	return &Config{
		PolicyFile: &policy.PolicyFile{
			Version: 1,
			Settings: policy.Settings{
				DefaultAction: api.VerdictDeny,
			},
		},
		LogDir:          expandHome(DefaultLogDir()),
		DashboardAddr:   DefaultDashboardAddr,
		ApprovalTimeout: DefaultApprovalTimeout,
		DefaultAction:   api.VerdictDeny,
	}
}

// MarshalYAML serializes the policy for display/export.
func (c *Config) MarshalYAML() ([]byte, error) {
	return yaml.Marshal(c.PolicyFile)
}
