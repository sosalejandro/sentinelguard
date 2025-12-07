package usecase

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
	"github.com/as-main/backdoor-checker/internal/domain/repository"
)

// TestMain ensures no goroutine leaks across all tests
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// mockScanner implements repository.Scanner for testing
type mockScanner struct {
	name        string
	description string
	category    entity.FindingCategory
	scanFunc    func(ctx context.Context) ([]*entity.Finding, error)
	scanCount   int32
}

func (m *mockScanner) Name() string                       { return m.name }
func (m *mockScanner) Description() string                { return m.description }
func (m *mockScanner) Category() entity.FindingCategory   { return m.category }
func (m *mockScanner) Scan(ctx context.Context) ([]*entity.Finding, error) {
	atomic.AddInt32(&m.scanCount, 1)
	if m.scanFunc != nil {
		return m.scanFunc(ctx)
	}
	return nil, nil
}

// mockRegistry implements repository.ScannerRegistry for testing
type mockRegistry struct {
	scanners map[string]repository.Scanner
}

func newMockRegistry() *mockRegistry {
	return &mockRegistry{
		scanners: make(map[string]repository.Scanner),
	}
}

func (r *mockRegistry) Register(scanner repository.Scanner) {
	r.scanners[scanner.Name()] = scanner
}

func (r *mockRegistry) Get(name string) (repository.Scanner, bool) {
	s, ok := r.scanners[name]
	return s, ok
}

func (r *mockRegistry) GetAll() []repository.Scanner {
	result := make([]repository.Scanner, 0, len(r.scanners))
	for _, s := range r.scanners {
		result = append(result, s)
	}
	return result
}

func (r *mockRegistry) GetByCategory(category entity.FindingCategory) []repository.Scanner {
	// For testing, return all scanners (category filtering not needed for leak tests)
	return r.GetAll()
}

// TestScanUseCase_NoGoroutineLeaks_NormalExecution tests that goroutines
// are properly cleaned up after normal scan execution
func TestScanUseCase_NoGoroutineLeaks_NormalExecution(t *testing.T) {
	registry := newMockRegistry()
	registry.Register(&mockScanner{
		name:        "test1",
		description: "Test scanner 1",
		scanFunc: func(ctx context.Context) ([]*entity.Finding, error) {
			return []*entity.Finding{
				{ID: "test-1", Category: entity.CategoryProcess, Severity: entity.SeverityLow},
			}, nil
		},
	})
	registry.Register(&mockScanner{
		name:        "test2",
		description: "Test scanner 2",
		scanFunc: func(ctx context.Context) ([]*entity.Finding, error) {
			return nil, nil
		},
	})

	uc := NewScanUseCase(registry)
	ctx := context.Background()

	result, errs := uc.Execute(ctx, &ScanOptions{
		Parallel:    true,
		MaxParallel: 5,
	})

	if errs != nil && errs.HasErrors() {
		t.Errorf("unexpected errors: %v", errs)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Summary.TotalFindings != 1 {
		t.Errorf("expected 1 finding, got %d", result.Summary.TotalFindings)
	}
}

// TestScanUseCase_NoGoroutineLeaks_ContextCancellation tests that goroutines
// are properly cleaned up when context is cancelled
func TestScanUseCase_NoGoroutineLeaks_ContextCancellation(t *testing.T) {
	registry := newMockRegistry()

	// Scanner that blocks until context is cancelled
	registry.Register(&mockScanner{
		name:        "slow",
		description: "Slow scanner",
		scanFunc: func(ctx context.Context) ([]*entity.Finding, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(10 * time.Second):
				return nil, nil
			}
		},
	})

	uc := NewScanUseCase(registry)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	result, errs := uc.Execute(ctx, &ScanOptions{
		Parallel:    true,
		MaxParallel: 5,
	})

	// Should complete (possibly with errors due to cancellation)
	if result == nil {
		t.Fatal("expected non-nil result even on cancellation")
	}

	// Errors are expected due to cancellation
	_ = errs
}

// TestScanUseCase_NoGoroutineLeaks_ScannerPanic tests that goroutines
// are properly cleaned up even if a scanner panics
func TestScanUseCase_NoGoroutineLeaks_ScannerError(t *testing.T) {
	registry := newMockRegistry()

	registry.Register(&mockScanner{
		name:        "error",
		description: "Error scanner",
		scanFunc: func(ctx context.Context) ([]*entity.Finding, error) {
			return nil, errors.New("scanner failed")
		},
	})
	registry.Register(&mockScanner{
		name:        "success",
		description: "Success scanner",
		scanFunc: func(ctx context.Context) ([]*entity.Finding, error) {
			return []*entity.Finding{
				{ID: "test-1", Category: entity.CategoryProcess, Severity: entity.SeverityLow},
			}, nil
		},
	})

	uc := NewScanUseCase(registry)
	ctx := context.Background()

	result, errs := uc.Execute(ctx, &ScanOptions{
		Parallel:    true,
		MaxParallel: 5,
	})

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if errs == nil || !errs.HasErrors() {
		t.Error("expected errors from failed scanner")
	}
}

// TestScanUseCase_NoGoroutineLeaks_SequentialMode tests sequential execution
func TestScanUseCase_NoGoroutineLeaks_SequentialMode(t *testing.T) {
	registry := newMockRegistry()
	scanOrder := make([]string, 0)

	registry.Register(&mockScanner{
		name:        "first",
		description: "First scanner",
		scanFunc: func(ctx context.Context) ([]*entity.Finding, error) {
			scanOrder = append(scanOrder, "first")
			return nil, nil
		},
	})
	registry.Register(&mockScanner{
		name:        "second",
		description: "Second scanner",
		scanFunc: func(ctx context.Context) ([]*entity.Finding, error) {
			scanOrder = append(scanOrder, "second")
			return nil, nil
		},
	})

	uc := NewScanUseCase(registry)
	ctx := context.Background()

	result, errs := uc.Execute(ctx, &ScanOptions{
		Parallel: false,
	})

	if errs != nil && errs.HasErrors() {
		t.Errorf("unexpected errors: %v", errs)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// TestScanUseCase_NoGoroutineLeaks_MaxParallelLimit tests semaphore limiting
func TestScanUseCase_NoGoroutineLeaks_MaxParallelLimit(t *testing.T) {
	registry := newMockRegistry()
	var concurrent int32
	var maxConcurrent int32

	for i := 0; i < 10; i++ {
		name := string(rune('a' + i))
		registry.Register(&mockScanner{
			name:        name,
			description: "Scanner " + name,
			scanFunc: func(ctx context.Context) ([]*entity.Finding, error) {
				current := atomic.AddInt32(&concurrent, 1)
				// Track max concurrency
				for {
					max := atomic.LoadInt32(&maxConcurrent)
					if current <= max || atomic.CompareAndSwapInt32(&maxConcurrent, max, current) {
						break
					}
				}
				time.Sleep(50 * time.Millisecond)
				atomic.AddInt32(&concurrent, -1)
				return nil, nil
			},
		})
	}

	uc := NewScanUseCase(registry)
	ctx := context.Background()

	result, errs := uc.Execute(ctx, &ScanOptions{
		Parallel:    true,
		MaxParallel: 3,
	})

	if errs != nil && errs.HasErrors() {
		t.Errorf("unexpected errors: %v", errs)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Verify concurrency was limited
	if atomic.LoadInt32(&maxConcurrent) > 3 {
		t.Errorf("max concurrency exceeded limit: got %d, want <= 3", maxConcurrent)
	}
}

// TestScanUseCase_NoGoroutineLeaks_EmptyRegistry tests with no scanners
func TestScanUseCase_NoGoroutineLeaks_EmptyRegistry(t *testing.T) {
	registry := newMockRegistry()
	uc := NewScanUseCase(registry)
	ctx := context.Background()

	result, errs := uc.Execute(ctx, nil)

	if errs != nil && errs.HasErrors() {
		t.Errorf("unexpected errors: %v", errs)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", result.Summary.TotalFindings)
	}
}
