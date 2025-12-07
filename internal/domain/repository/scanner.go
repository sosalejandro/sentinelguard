package repository

import (
	"context"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

type Scanner interface {
	Name() string
	Description() string
	Category() entity.FindingCategory
	Scan(ctx context.Context) ([]*entity.Finding, error)
}

type ScannerRegistry interface {
	Register(scanner Scanner)
	Get(name string) (Scanner, bool)
	GetAll() []Scanner
	GetByCategory(category entity.FindingCategory) []Scanner
}
