package entity

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type ScanStatus string

const (
	StatusPending   ScanStatus = "PENDING"
	StatusRunning   ScanStatus = "RUNNING"
	StatusCompleted ScanStatus = "COMPLETED"
	StatusFailed    ScanStatus = "FAILED"
)

// ScanResult holds the results of a security scan.
// All methods are thread-safe for concurrent access.
type ScanResult struct {
	mu        sync.Mutex
	ID        string
	Status    ScanStatus
	StartTime time.Time
	EndTime   time.Time
	Findings  []*Finding
	Summary   *ScanSummary
	Error     error
}

type ScanSummary struct {
	TotalFindings    int
	CriticalCount    int
	HighCount        int
	MediumCount      int
	LowCount         int
	InfoCount        int
	ScannersExecuted []string
	Duration         time.Duration
}

func NewScanResult() *ScanResult {
	return &ScanResult{
		ID:        generateScanID(),
		Status:    StatusPending,
		StartTime: time.Now(),
		Findings:  make([]*Finding, 0),
		Summary:   &ScanSummary{},
	}
}

// AddFinding adds a single finding to the result (thread-safe).
func (sr *ScanResult) AddFinding(f *Finding) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.Findings = append(sr.Findings, f)
	sr.updateSummary(f)
}

// AddFindings adds multiple findings to the result (thread-safe).
func (sr *ScanResult) AddFindings(findings []*Finding) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	for _, f := range findings {
		sr.Findings = append(sr.Findings, f)
		sr.updateSummary(f)
	}
}

// GetFindings returns a copy of all findings (thread-safe).
func (sr *ScanResult) GetFindings() []*Finding {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	result := make([]*Finding, len(sr.Findings))
	copy(result, sr.Findings)
	return result
}

// Complete marks the scan as completed (thread-safe).
func (sr *ScanResult) Complete() {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.EndTime = time.Now()
	sr.Status = StatusCompleted
	sr.Summary.Duration = sr.EndTime.Sub(sr.StartTime)
}

// Fail marks the scan as failed with an error (thread-safe).
func (sr *ScanResult) Fail(err error) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.EndTime = time.Now()
	sr.Status = StatusFailed
	sr.Error = err
	sr.Summary.Duration = sr.EndTime.Sub(sr.StartTime)
}

func (sr *ScanResult) updateSummary(f *Finding) {
	sr.Summary.TotalFindings++
	switch f.Severity {
	case SeverityCritical:
		sr.Summary.CriticalCount++
	case SeverityHigh:
		sr.Summary.HighCount++
	case SeverityMedium:
		sr.Summary.MediumCount++
	case SeverityLow:
		sr.Summary.LowCount++
	case SeverityInfo:
		sr.Summary.InfoCount++
	}
}

// HasCriticalFindings returns true if any critical findings exist (thread-safe).
func (sr *ScanResult) HasCriticalFindings() bool {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	return sr.Summary.CriticalCount > 0
}

// HasHighFindings returns true if any high severity findings exist (thread-safe).
func (sr *ScanResult) HasHighFindings() bool {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	return sr.Summary.HighCount > 0
}

var scanIDCounter int64

func generateScanID() string {
	id := atomic.AddInt64(&scanIDCounter, 1)
	return fmt.Sprintf("SCAN-%06d", id)
}
