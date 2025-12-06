package repository

import (
	"io"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

type Reporter interface {
	Report(result *entity.ScanResult, w io.Writer) error
	Format() string
}
