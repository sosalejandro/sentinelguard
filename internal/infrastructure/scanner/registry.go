package scanner

import (
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

func (r *Registry) GetAll() []repository.Scanner {
	r.mu.RLock()
	defer r.mu.RUnlock()

	scanners := make([]repository.Scanner, 0, len(r.scanners))
	for _, s := range r.scanners {
		scanners = append(scanners, s)
	}
	return scanners
}

func (r *Registry) GetByCategory(category entity.FindingCategory) []repository.Scanner {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var scanners []repository.Scanner
	for _, s := range r.scanners {
		if s.Category() == category {
			scanners = append(scanners, s)
		}
	}
	return scanners
}
