package usecase

import (
	"context"
	"fmt"
	"sync"

	"go.uber.org/zap"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
	"github.com/as-main/backdoor-checker/internal/domain/repository"
	"github.com/as-main/backdoor-checker/pkg/logger"
)

type ScanUseCase struct {
	registry repository.ScannerRegistry
	log      *zap.Logger
}

func NewScanUseCase(registry repository.ScannerRegistry) *ScanUseCase {
	return &ScanUseCase{
		registry: registry,
		log:      logger.Get().With(zap.String("component", "scan_usecase")),
	}
}

type ScanOptions struct {
	Scanners    []string
	Parallel    bool
	MaxParallel int
}

func DefaultScanOptions() *ScanOptions {
	return &ScanOptions{
		Scanners:    nil,
		Parallel:    true,
		MaxParallel: 5,
	}
}

type scannerResult struct {
	scannerName string
	findings    []*entity.Finding
	err         error
}

type ScanError struct {
	ScannerName string
	Err         error
}

func (e *ScanError) Error() string {
	return fmt.Sprintf("scanner %s failed: %v", e.ScannerName, e.Err)
}

type ScanErrors struct {
	Errors []*ScanError
}

func (e *ScanErrors) Error() string {
	if len(e.Errors) == 0 {
		return "no errors"
	}
	return fmt.Sprintf("%d scanner(s) failed", len(e.Errors))
}

func (e *ScanErrors) Add(scannerName string, err error) {
	e.Errors = append(e.Errors, &ScanError{
		ScannerName: scannerName,
		Err:         err,
	})
}

func (e *ScanErrors) HasErrors() bool {
	return len(e.Errors) > 0
}

func (uc *ScanUseCase) Execute(ctx context.Context, opts *ScanOptions) (*entity.ScanResult, *ScanErrors) {
	if opts == nil {
		opts = DefaultScanOptions()
	}

	result := entity.NewScanResult()
	result.Status = entity.StatusRunning
	scanErrors := &ScanErrors{}

	scanners := uc.getScanners(opts.Scanners)
	if len(scanners) == 0 {
		uc.log.Warn("no scanners to execute")
		result.Complete()
		return result, nil
	}

	uc.log.Info("starting scan",
		zap.Int("scanner_count", len(scanners)),
		zap.Bool("parallel", opts.Parallel),
		zap.Int("max_parallel", opts.MaxParallel),
	)

	for _, s := range scanners {
		result.Summary.ScannersExecuted = append(result.Summary.ScannersExecuted, s.Name())
	}

	if opts.Parallel {
		uc.runParallel(ctx, scanners, result, scanErrors, opts.MaxParallel)
	} else {
		uc.runSequential(ctx, scanners, result, scanErrors)
	}

	result.Complete()

	uc.log.Info("scan completed",
		zap.Int("total_findings", result.Summary.TotalFindings),
		zap.Int("critical", result.Summary.CriticalCount),
		zap.Int("high", result.Summary.HighCount),
		zap.Int("errors", len(scanErrors.Errors)),
		zap.Duration("duration", result.Summary.Duration),
	)

	if scanErrors.HasErrors() {
		return result, scanErrors
	}
	return result, nil
}

func (uc *ScanUseCase) getScanners(names []string) []repository.Scanner {
	if len(names) == 0 {
		return uc.registry.GetAll()
	}

	scanners := make([]repository.Scanner, 0, len(names))
	for _, name := range names {
		if s, ok := uc.registry.Get(name); ok {
			scanners = append(scanners, s)
		} else {
			uc.log.Warn("scanner not found", zap.String("name", name))
		}
	}
	return scanners
}

func (uc *ScanUseCase) runSequential(ctx context.Context, scanners []repository.Scanner, result *entity.ScanResult, scanErrors *ScanErrors) {
	for _, scanner := range scanners {
		select {
		case <-ctx.Done():
			uc.log.Info("scan cancelled")
			return
		default:
			uc.log.Debug("running scanner", zap.String("scanner", scanner.Name()))

			findings, err := scanner.Scan(ctx)
			if err != nil {
				uc.log.Error("scanner failed",
					zap.String("scanner", scanner.Name()),
					zap.Error(err),
				)
				scanErrors.Add(scanner.Name(), err)
				continue
			}

			uc.log.Debug("scanner completed",
				zap.String("scanner", scanner.Name()),
				zap.Int("findings", len(findings)),
			)
			result.AddFindings(findings)
		}
	}
}

func (uc *ScanUseCase) runParallel(ctx context.Context, scanners []repository.Scanner, result *entity.ScanResult, scanErrors *ScanErrors, maxParallel int) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxParallel)
	resultsChan := make(chan scannerResult, len(scanners))

	for _, scanner := range scanners {
		wg.Add(1)
		go func(s repository.Scanner) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				resultsChan <- scannerResult{
					scannerName: s.Name(),
					err:         ctx.Err(),
				}
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			uc.log.Debug("running scanner", zap.String("scanner", s.Name()))

			findings, err := s.Scan(ctx)
			resultsChan <- scannerResult{
				scannerName: s.Name(),
				findings:    findings,
				err:         err,
			}
		}(scanner)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var mu sync.Mutex
	for res := range resultsChan {
		if res.err != nil {
			uc.log.Error("scanner failed",
				zap.String("scanner", res.scannerName),
				zap.Error(res.err),
			)
			mu.Lock()
			scanErrors.Add(res.scannerName, res.err)
			mu.Unlock()
			continue
		}

		uc.log.Debug("scanner completed",
			zap.String("scanner", res.scannerName),
			zap.Int("findings", len(res.findings)),
		)

		mu.Lock()
		result.AddFindings(res.findings)
		mu.Unlock()
	}
}

func (uc *ScanUseCase) ListScanners() []repository.Scanner {
	return uc.registry.GetAll()
}
