package policy

import (
	"fmt"
	"os"
	"regexp"

	"github.com/tkingovr/agent-guard/api"
	"gopkg.in/yaml.v3"
)

// LoadFile reads and validates a YAML policy file.
func LoadFile(path string) (*PolicyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}
	return LoadBytes(data)
}

// LoadBytes parses and validates YAML policy data.
func LoadBytes(data []byte) (*PolicyFile, error) {
	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parsing policy YAML: %w", err)
	}
	if err := validate(&pf); err != nil {
		return nil, err
	}
	return &pf, nil
}

func validate(pf *PolicyFile) error {
	if pf.Version != 1 {
		return fmt.Errorf("unsupported policy version: %d (expected 1)", pf.Version)
	}

	if pf.Settings.DefaultAction == "" {
		pf.Settings.DefaultAction = api.VerdictDeny
	}

	validActions := map[string]bool{
		"allow": true, "deny": true, "ask": true, "log": true,
	}

	for i, rule := range pf.Rules {
		if rule.Name == "" {
			return fmt.Errorf("rule %d: name is required", i)
		}
		if !validActions[rule.Action] {
			return fmt.Errorf("rule %q: invalid action %q", rule.Name, rule.Action)
		}
		if rule.Match.Method == "" {
			return fmt.Errorf("rule %q: match.method is required", rule.Name)
		}
		// Validate regex patterns compile
		for key, am := range rule.Match.Arguments {
			if am.Regex != "" {
				if _, err := regexp.Compile(am.Regex); err != nil {
					return fmt.Errorf("rule %q: argument %q regex invalid: %w", rule.Name, key, err)
				}
			}
		}
	}

	return nil
}
