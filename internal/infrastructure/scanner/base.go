package scanner

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/as-main/backdoor-checker/pkg/logger"
)

type BaseScanner struct {
	name        string
	description string
	log         *zap.Logger
}

func NewBaseScanner(name, description string) BaseScanner {
	return BaseScanner{
		name:        name,
		description: description,
		log:         logger.Get().With(zap.String("scanner", name)),
	}
}

func (b *BaseScanner) Name() string {
	return b.name
}

func (b *BaseScanner) Description() string {
	return b.description
}

func (b *BaseScanner) Logger() *zap.Logger {
	return b.log
}

func (b *BaseScanner) RunCommand(ctx context.Context, name string, args ...string) ([]string, error) {
	b.log.Debug("executing command",
		zap.String("command", name),
		zap.Strings("args", args),
	)

	start := time.Now()
	cmd := exec.CommandContext(ctx, name, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	duration := time.Since(start)

	b.log.Debug("command completed",
		zap.Duration("duration", duration),
		zap.Int("stdout_bytes", stdout.Len()),
		zap.Int("stderr_bytes", stderr.Len()),
	)

	if err != nil {
		if ctx.Err() != nil {
			b.log.Debug("command cancelled", zap.Error(ctx.Err()))
			return nil, ctx.Err()
		}
		b.log.Debug("command error", zap.Error(err), zap.String("stderr", stderr.String()))
		// Return error so callers can handle it appropriately
		return nil, err
	}

	var lines []string
	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	return lines, nil
}

func (b *BaseScanner) FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (b *BaseScanner) ReadFile(ctx context.Context, path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

// ExecCommand executes a command and returns combined output as a string
func (b *BaseScanner) ExecCommand(ctx context.Context, name string, args ...string) (string, error) {
	lines, err := b.RunCommand(ctx, name, args...)
	if err != nil {
		return "", err
	}
	return strings.Join(lines, "\n"), nil
}
