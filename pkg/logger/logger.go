package logger

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var globalLogger *zap.Logger

func Init(debug bool) {
	var config zap.Config

	if debug {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		config.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	} else {
		config = zap.NewProductionConfig()
		config.Level = zap.NewAtomicLevelAt(zapcore.WarnLevel)
		config.EncoderConfig.TimeKey = ""
		config.EncoderConfig.CallerKey = ""
	}

	config.OutputPaths = []string{"stdout"}
	config.ErrorOutputPaths = []string{"stderr"}

	var err error
	globalLogger, err = config.Build()
	if err != nil {
		globalLogger = zap.NewNop()
		os.Stderr.WriteString("failed to initialize logger: " + err.Error() + "\n")
	}
}

func Get() *zap.Logger {
	if globalLogger == nil {
		Init(false)
	}
	return globalLogger
}

func Debug(msg string, fields ...zap.Field) {
	Get().Debug(msg, fields...)
}

func Info(msg string, fields ...zap.Field) {
	Get().Info(msg, fields...)
}

func Warn(msg string, fields ...zap.Field) {
	Get().Warn(msg, fields...)
}

func Error(msg string, fields ...zap.Field) {
	Get().Error(msg, fields...)
}

func Fatal(msg string, fields ...zap.Field) {
	Get().Fatal(msg, fields...)
}

func With(fields ...zap.Field) *zap.Logger {
	return Get().With(fields...)
}

func Sync() {
	if globalLogger != nil {
		_ = globalLogger.Sync()
	}
}
