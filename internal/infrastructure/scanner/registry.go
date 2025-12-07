package scanner

import (
	"sort"
	"sync"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
	"github.com/as-main/backdoor-checker/internal/domain/repository"
)

type Registry struct {
	mu       sync.RWMutex
	scanners map[string]repository.Scanner
}

func NewRegistry() *Registry {
	return &Registry{
		scanners: make(map[string]repository.Scanner),
	}
}

func (r *Registry) Register(scanner repository.Scanner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanners[scanner.Name()] = scanner
}

func (r *Registry) Get(name string) (repository.Scanner, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.scanners[name]
	return s, ok
}

// GetAll returns all registered scanners in deterministic order (sorted by name).
func (r *Registry) GetAll() []repository.Scanner {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Collect names for deterministic ordering
	names := make([]string, 0, len(r.scanners))
	for name := range r.scanners {
		names = append(names, name)
	}
	sort.Strings(names)

	// Build result in sorted order
	scanners := make([]repository.Scanner, 0, len(r.scanners))
	for _, name := range names {
		scanners = append(scanners, r.scanners[name])
	}
	return scanners
}

// GetByCategory returns scanners matching the category in deterministic order.
func (r *Registry) GetByCategory(category entity.FindingCategory) []repository.Scanner {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Collect matching scanner names for deterministic ordering
	var names []string
	for name, s := range r.scanners {
		if s.Category() == category {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	// Build result in sorted order
	scanners := make([]repository.Scanner, 0, len(names))
	for _, name := range names {
		scanners = append(scanners, r.scanners[name])
	}
	return scanners
}
