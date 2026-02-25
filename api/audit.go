package api

import "time"

// QueryFilter defines criteria for querying audit records.
type QueryFilter struct {
	Since   time.Time `json:"since,omitempty"`
	Until   time.Time `json:"until,omitempty"`
	Method  string    `json:"method,omitempty"`
	Tool    string    `json:"tool,omitempty"`
	Verdict Verdict   `json:"verdict,omitempty"`
	Limit   int       `json:"limit,omitempty"`
	Offset  int       `json:"offset,omitempty"`
}

// AuditStats provides summary statistics for the dashboard.
type AuditStats struct {
	TotalRequests int            `json:"total_requests"`
	AllowCount    int            `json:"allow_count"`
	DenyCount     int            `json:"deny_count"`
	AskCount      int            `json:"ask_count"`
	LogCount      int            `json:"log_count"`
	ByMethod      map[string]int `json:"by_method"`
	ByTool        map[string]int `json:"by_tool"`
}
