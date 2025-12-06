package entity

import (
	"fmt"
	"time"
)

type ScanStatus string

const (
	StatusPending   ScanStatus = "PENDING"
	StatusRunning   ScanStatus = "RUNNING"
	StatusCompleted ScanStatus = "COMPLETED"
	StatusFailed    ScanStatus = "FAILED"
)

type ScanResult struct {
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

func (sr *ScanResult) AddFinding(f *Finding) {
	sr.Findings = append(sr.Findings, f)
	sr.updateSummary(f)
}

func (sr *ScanResult) AddFindings(findings []*Finding) {
	for _, f := range findings {
		sr.AddFinding(f)
	}
}

func (sr *ScanResult) Complete() {
	sr.EndTime = time.Now()
	sr.Status = StatusCompleted
	sr.Summary.Duration = sr.EndTime.Sub(sr.StartTime)
}

func (sr *ScanResult) Fail(err error) {
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

func (sr *ScanResult) HasCriticalFindings() bool {
	return sr.Summary.CriticalCount > 0
}

func (sr *ScanResult) HasHighFindings() bool {
	return sr.Summary.HighCount > 0
}

var scanIDCounter int

func generateScanID() string {
	scanIDCounter++
	return fmt.Sprintf("SCAN-%06d", scanIDCounter)
}
