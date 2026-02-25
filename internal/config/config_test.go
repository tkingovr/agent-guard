package config

import (
	"testing"
	"time"

	"github.com/aqubia/agent-guard/api"
)

func TestLoadBytes_DefaultDeny(t *testing.T) {
	yaml := `
version: 1
settings:
  default_action: deny
  approval_timeout: "10m"
rules:
  - name: allow-init
    match:
      method: initialize
    action: allow
`
	cfg, err := LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultAction != api.VerdictDeny {
		t.Errorf("expected deny default, got %s", cfg.DefaultAction)
	}
	if cfg.ApprovalTimeout != 10*time.Minute {
		t.Errorf("expected 10m timeout, got %s", cfg.ApprovalTimeout)
	}
}

func TestLoadBytes_Defaults(t *testing.T) {
	yaml := `
version: 1
settings: {}
rules:
  - name: allow-init
    match:
      method: initialize
    action: allow
`
	cfg, err := LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DashboardAddr != DefaultDashboardAddr {
		t.Errorf("expected default dashboard addr %s, got %s", DefaultDashboardAddr, cfg.DashboardAddr)
	}
	if cfg.ApprovalTimeout != DefaultApprovalTimeout {
		t.Errorf("expected default approval timeout %s, got %s", DefaultApprovalTimeout, cfg.ApprovalTimeout)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.DefaultAction != api.VerdictDeny {
		t.Errorf("expected deny default, got %s", cfg.DefaultAction)
	}
	if cfg.PolicyFile == nil {
		t.Fatal("expected non-nil policy file")
	}
}

func TestLoadBytes_InvalidTimeout(t *testing.T) {
	yaml := `
version: 1
settings:
  approval_timeout: "invalid"
rules:
  - name: allow-init
    match:
      method: initialize
    action: allow
`
	_, err := LoadBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid timeout")
	}
}
