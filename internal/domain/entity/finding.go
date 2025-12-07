package entity

import (
	"fmt"
	"sync/atomic"
	"time"
)

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

type FindingCategory string

const (
	CategoryNetwork     FindingCategory = "NETWORK"
	CategoryProcess     FindingCategory = "PROCESS"
	CategoryCron        FindingCategory = "CRON"
	CategorySSH         FindingCategory = "SSH"
	CategoryStartup     FindingCategory = "STARTUP"
	CategoryFileSystem  FindingCategory = "FILESYSTEM"
	CategoryUser        FindingCategory = "USER"
	CategoryPersistence FindingCategory = "PERSISTENCE"
	CategoryRootkit     FindingCategory = "ROOTKIT"
	CategoryPDF         FindingCategory = "PDF"
	CategoryKernel      FindingCategory = "KERNEL"
	CategoryMemory      FindingCategory = "MEMORY"
	CategoryPAM         FindingCategory = "PAM"
	CategoryBoot        FindingCategory = "BOOT"
	CategoryIntegrity   FindingCategory = "INTEGRITY"
)

type Finding struct {
	ID          string
	Category    FindingCategory
	Severity    Severity
	Title       string
	Description string
	Path        string
	Details     map[string]interface{}
	Timestamp   time.Time
}

func NewFinding(category FindingCategory, severity Severity, title, description string) *Finding {
	return &Finding{
		ID:          generateID(),
		Category:    category,
		Severity:    severity,
		Title:       title,
		Description: description,
		Details:     make(map[string]interface{}),
		Timestamp:   time.Now(),
	}
}

func (f *Finding) WithPath(path string) *Finding {
	f.Path = path
	return f
}

func (f *Finding) WithDetail(key string, value interface{}) *Finding {
	f.Details[key] = value
	return f
}

var idCounter int64

func generateID() string {
	id := atomic.AddInt64(&idCounter, 1)
	return fmt.Sprintf("FIND-%06d", id)
}
