package scanner

import (
	"context"
	"sync"
	"testing"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
	"github.com/as-main/backdoor-checker/internal/domain/repository"
)

// mockScanner for testing
type testScanner struct {
	name        string
	description string
	category    entity.FindingCategory
}

func (s *testScanner) Name() string                                            { return s.name }
func (s *testScanner) Description() string                                     { return s.description }
func (s *testScanner) Category() entity.FindingCategory                        { return s.category }
func (s *testScanner) Scan(ctx context.Context) ([]*entity.Finding, error)     { return nil, nil }

func TestRegistry_Register_And_Get(t *testing.T) {
	registry := NewRegistry()

	scanner := &testScanner{
		name:        "test-scanner",
		description: "Test scanner",
		category:    entity.CategoryNetwork,
	}

	registry.Register(scanner)

	got, ok := registry.Get("test-scanner")
	if !ok {
		t.Fatal("expected scanner to be found")
	}
	if got.Name() != "test-scanner" {
		t.Errorf("expected name 'test-scanner', got %q", got.Name())
	}
}

func TestRegistry_Get_NotFound(t *testing.T) {
	registry := NewRegistry()

	_, ok := registry.Get("nonexistent")
	if ok {
		t.Error("expected scanner to not be found")
	}
}

func TestRegistry_GetAll_DeterministicOrder(t *testing.T) {
	registry := NewRegistry()

	// Register in random order
	names := []string{"zebra", "alpha", "mike", "bravo"}
	for _, name := range names {
		registry.Register(&testScanner{
			name:     name,
			category: entity.CategoryNetwork,
		})
	}

	// GetAll should return in sorted order
	scanners := registry.GetAll()
	if len(scanners) != 4 {
		t.Fatalf("expected 4 scanners, got %d", len(scanners))
	}

	expected := []string{"alpha", "bravo", "mike", "zebra"}
	for i, s := range scanners {
		if s.Name() != expected[i] {
			t.Errorf("position %d: expected %q, got %q", i, expected[i], s.Name())
		}
	}

	// Run multiple times to verify determinism
	for i := 0; i < 10; i++ {
		scanners2 := registry.GetAll()
		for j, s := range scanners2 {
			if s.Name() != expected[j] {
				t.Errorf("iteration %d, position %d: expected %q, got %q", i, j, expected[j], s.Name())
			}
		}
	}
}

func TestRegistry_GetByCategory_DeterministicOrder(t *testing.T) {
	registry := NewRegistry()

	// Register scanners with different categories
	registry.Register(&testScanner{name: "z-network", category: entity.CategoryNetwork})
	registry.Register(&testScanner{name: "a-network", category: entity.CategoryNetwork})
	registry.Register(&testScanner{name: "process", category: entity.CategoryProcess})
	registry.Register(&testScanner{name: "m-network", category: entity.CategoryNetwork})

	// GetByCategory should return sorted
	networkScanners := registry.GetByCategory(entity.CategoryNetwork)
	if len(networkScanners) != 3 {
		t.Fatalf("expected 3 network scanners, got %d", len(networkScanners))
	}

	expected := []string{"a-network", "m-network", "z-network"}
	for i, s := range networkScanners {
		if s.Name() != expected[i] {
			t.Errorf("position %d: expected %q, got %q", i, expected[i], s.Name())
		}
	}
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	registry := NewRegistry()
	var wg sync.WaitGroup

	// Concurrent writes
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			registry.Register(&testScanner{
				name:     "scanner-" + string(rune('a'+id%26)),
				category: entity.CategoryNetwork,
			})
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = registry.GetAll()
			_ = registry.GetByCategory(entity.CategoryNetwork)
		}()
	}

	wg.Wait()
}

func TestRegistry_ImplementsScannerRegistry(t *testing.T) {
	// Compile-time check that Registry implements ScannerRegistry
	var _ repository.ScannerRegistry = (*Registry)(nil)
}
