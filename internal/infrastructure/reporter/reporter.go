package reporter

import (
	"fmt"
	"io"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

// Reporter interface defines the contract for all reporters
type Reporter interface {
	// Format returns the name of the output format
	Format() string
	// Report outputs the scan result to the provided writer
	Report(result *entity.ScanResult, w io.Writer) error
}

// Factory creates reporters based on format name
type Factory struct{}

// NewFactory creates a new reporter factory
func NewFactory() *Factory {
	return &Factory{}
}

// Create returns a reporter for the given format
func (f *Factory) Create(format string, verbose bool, pretty bool) (Reporter, error) {
	switch format {
	case "console", "":
		return NewConsoleReporter(verbose), nil
	case "json":
		return NewJSONReporter(pretty), nil
	case "yaml":
		return NewYAMLReporter(), nil
	default:
		return nil, fmt.Errorf("unsupported output format: %s (supported: console, json, yaml)", format)
	}
}

// SupportedFormats returns a list of supported output formats
func SupportedFormats() []string {
	return []string{"console", "json", "yaml"}
}
