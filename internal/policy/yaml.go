package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sync"

	"github.com/aqubia/agent-guard/api"
)

// YAMLEngine implements first-match-wins policy evaluation using YAML rules.
type YAMLEngine struct {
	mu   sync.RWMutex
	file *PolicyFile
	path string

	// compiled regex cache
	regexCache map[string]*regexp.Regexp
}

// NewYAMLEngine creates a new YAML policy engine from a file path.
func NewYAMLEngine(path string) (*YAMLEngine, error) {
	e := &YAMLEngine{path: path}
	if err := e.Reload(context.Background()); err != nil {
		return nil, err
	}
	return e, nil
}

// NewYAMLEngineFromPolicy creates a new YAML policy engine from an already-loaded policy.
func NewYAMLEngineFromPolicy(pf *PolicyFile) (*YAMLEngine, error) {
	e := &YAMLEngine{}
	e.file = pf
	e.regexCache = make(map[string]*regexp.Regexp)
	if err := e.compileRegexes(); err != nil {
		return nil, err
	}
	return e, nil
}

// Evaluate checks the input against rules in order, returning the first match.
func (e *YAMLEngine) Evaluate(_ context.Context, input *EvalInput) (*EvalResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.file.Rules {
		if e.matches(&rule, input) {
			return &EvalResult{
				Verdict: api.Verdict(rule.Action),
				Rule:    rule.Name,
				Message: rule.Message,
			}, nil
		}
	}

	// No rule matched — use default action
	return &EvalResult{
		Verdict: e.file.Settings.DefaultAction,
		Rule:    "_default",
		Message: "no matching rule; default action applied",
	}, nil
}

// Reload re-reads the policy file from disk.
func (e *YAMLEngine) Reload(_ context.Context) error {
	if e.path == "" {
		return nil
	}
	pf, err := LoadFile(e.path)
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.file = pf
	e.regexCache = make(map[string]*regexp.Regexp)
	return e.compileRegexes()
}

// Policy returns the current loaded policy (for dashboard display).
func (e *YAMLEngine) Policy() *PolicyFile {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.file
}

func (e *YAMLEngine) compileRegexes() error {
	for _, rule := range e.file.Rules {
		for key, am := range rule.Match.Arguments {
			if am.Regex != "" {
				cacheKey := rule.Name + ":" + key
				re, err := regexp.Compile(am.Regex)
				if err != nil {
					return fmt.Errorf("rule %q argument %q: %w", rule.Name, key, err)
				}
				e.regexCache[cacheKey] = re
			}
		}
	}
	return nil
}

func (e *YAMLEngine) matches(rule *Rule, input *EvalInput) bool {
	// Match method
	if rule.Match.Method != "" && rule.Match.Method != input.Method {
		return false
	}

	// Match tool name
	if rule.Match.Tool != "" && rule.Match.Tool != input.Tool {
		return false
	}

	// Match arguments
	if len(rule.Match.Arguments) > 0 {
		if input.Arguments == nil {
			return false
		}

		var args map[string]any
		if err := json.Unmarshal(input.Arguments, &args); err != nil {
			return false
		}

		for key, am := range rule.Match.Arguments {
			if key == "_any_value" {
				if !e.matchAnyValue(rule.Name, key, am, args) {
					return false
				}
			} else {
				val, ok := args[key]
				if !ok {
					return false
				}
				if !e.matchArgument(rule.Name, key, am, val) {
					return false
				}
			}
		}
	}

	return true
}

func (e *YAMLEngine) matchAnyValue(ruleName, matchKey string, am ArgumentMatch, args map[string]any) bool {
	for _, v := range args {
		if e.matchArgument(ruleName, matchKey, am, v) {
			return true
		}
	}
	return false
}

func (e *YAMLEngine) matchArgument(ruleName, key string, am ArgumentMatch, val any) bool {
	str := fmt.Sprintf("%v", val)

	if am.Exact != "" {
		return str == am.Exact
	}

	if am.Regex != "" {
		cacheKey := ruleName + ":" + key
		re, ok := e.regexCache[cacheKey]
		if !ok {
			return false
		}
		return re.MatchString(str)
	}

	return true
}
