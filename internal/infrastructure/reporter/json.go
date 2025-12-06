package reporter

import (
	"encoding/json"
	"io"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

// JSONReporter outputs scan results in JSON format
type JSONReporter struct {
	pretty bool
}

// NewJSONReporter creates a new JSON reporter
func NewJSONReporter(pretty bool) *JSONReporter {
	return &JSONReporter{
		pretty: pretty,
	}
}

// Format returns the format name
func (r *JSONReporter) Format() string {
	return "json"
}

// Report outputs the scan result as JSON
func (r *JSONReporter) Report(result *entity.ScanResult, w io.Writer) error {
	// Convert to a serializable structure
	output := r.toJSONOutput(result)

	encoder := json.NewEncoder(w)
	if r.pretty {
		encoder.SetIndent("", "  ")
	}

	return encoder.Encode(output)
}

// JSONOutput represents the JSON-serializable output structure
type JSONOutput struct {
	ScanID    string       `json:"scan_id"`
	StartTime string       `json:"start_time"`
	EndTime   string       `json:"end_time"`
	Duration  string       `json:"duration"`
	Status    string       `json:"status"`
	Summary   JSONSummary  `json:"summary"`
	Findings  []JSONFinding `json:"findings"`
}

// JSONSummary represents the summary in JSON format
type JSONSummary struct {
	TotalFindings    int      `json:"total_findings"`
	CriticalCount    int      `json:"critical_count"`
	HighCount        int      `json:"high_count"`
	MediumCount      int      `json:"medium_count"`
	LowCount         int      `json:"low_count"`
	InfoCount        int      `json:"info_count"`
	ScannersExecuted []string `json:"scanners_executed"`
}

// JSONFinding represents a single finding in JSON format
type JSONFinding struct {
	ID          string                 `json:"id"`
	Category    string                 `json:"category"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Path        string                 `json:"path,omitempty"`
	Timestamp   string                 `json:"timestamp"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

func (r *JSONReporter) toJSONOutput(result *entity.ScanResult) *JSONOutput {
	findings := make([]JSONFinding, 0, len(result.Findings))
	for _, f := range result.Findings {
		findings = append(findings, JSONFinding{
			ID:          f.ID,
			Category:    string(f.Category),
			Severity:    f.Severity.String(),
			Title:       f.Title,
			Description: f.Description,
			Path:        f.Path,
			Timestamp:   f.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
			Details:     f.Details,
		})
	}

	return &JSONOutput{
		ScanID:    result.ID,
		StartTime: result.StartTime.Format("2006-01-02T15:04:05Z07:00"),
		EndTime:   result.EndTime.Format("2006-01-02T15:04:05Z07:00"),
		Duration:  result.Summary.Duration.String(),
		Status:    string(result.Status),
		Summary: JSONSummary{
			TotalFindings:    result.Summary.TotalFindings,
			CriticalCount:    result.Summary.CriticalCount,
			HighCount:        result.Summary.HighCount,
			MediumCount:      result.Summary.MediumCount,
			LowCount:         result.Summary.LowCount,
			InfoCount:        result.Summary.InfoCount,
			ScannersExecuted: result.Summary.ScannersExecuted,
		},
		Findings: findings,
	}
}
