package reporter

import (
	"io"

	"gopkg.in/yaml.v3"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

// YAMLReporter outputs scan results in YAML format
type YAMLReporter struct{}

// NewYAMLReporter creates a new YAML reporter
func NewYAMLReporter() *YAMLReporter {
	return &YAMLReporter{}
}

// Format returns the format name
func (r *YAMLReporter) Format() string {
	return "yaml"
}

// Report outputs the scan result as YAML
func (r *YAMLReporter) Report(result *entity.ScanResult, w io.Writer) error {
	output := r.toYAMLOutput(result)

	encoder := yaml.NewEncoder(w)
	encoder.SetIndent(2)
	defer encoder.Close()

	return encoder.Encode(output)
}

// YAMLOutput represents the YAML-serializable output structure
type YAMLOutput struct {
	ScanID    string        `yaml:"scan_id"`
	StartTime string        `yaml:"start_time"`
	EndTime   string        `yaml:"end_time"`
	Duration  string        `yaml:"duration"`
	Status    string        `yaml:"status"`
	Summary   YAMLSummary   `yaml:"summary"`
	Findings  []YAMLFinding `yaml:"findings,omitempty"`
}

// YAMLSummary represents the summary in YAML format
type YAMLSummary struct {
	TotalFindings    int      `yaml:"total_findings"`
	CriticalCount    int      `yaml:"critical_count"`
	HighCount        int      `yaml:"high_count"`
	MediumCount      int      `yaml:"medium_count"`
	LowCount         int      `yaml:"low_count"`
	InfoCount        int      `yaml:"info_count"`
	ScannersExecuted []string `yaml:"scanners_executed"`
}

// YAMLFinding represents a single finding in YAML format
type YAMLFinding struct {
	ID          string                 `yaml:"id"`
	Category    string                 `yaml:"category"`
	Severity    string                 `yaml:"severity"`
	Title       string                 `yaml:"title"`
	Description string                 `yaml:"description"`
	Path        string                 `yaml:"path,omitempty"`
	Timestamp   string                 `yaml:"timestamp"`
	Details     map[string]interface{} `yaml:"details,omitempty"`
}

func (r *YAMLReporter) toYAMLOutput(result *entity.ScanResult) *YAMLOutput {
	findings := make([]YAMLFinding, 0, len(result.Findings))
	for _, f := range result.Findings {
		findings = append(findings, YAMLFinding{
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

	return &YAMLOutput{
		ScanID:    result.ID,
		StartTime: result.StartTime.Format("2006-01-02T15:04:05Z07:00"),
		EndTime:   result.EndTime.Format("2006-01-02T15:04:05Z07:00"),
		Duration:  result.Summary.Duration.String(),
		Status:    string(result.Status),
		Summary: YAMLSummary{
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
