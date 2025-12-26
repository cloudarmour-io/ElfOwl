// ANCHOR: Structured logging setup - Dec 26, 2025
// Provides centralized zap logger configuration for elf-owl
// Supports JSON and text output formats with configurable log levels

package logger

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// NewLogger creates a new structured logger with the specified level
func NewLogger(level string) (*zap.Logger, error) {
	// Parse log level
	logLevel, err := zapcore.ParseLevel(level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %s", level)
	}

	// Create production config with JSON output
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(logLevel)

	// Enable development mode features for debugging
	if logLevel == zapcore.DebugLevel {
		config = zap.NewDevelopmentConfig()
		config.Level = zap.NewAtomicLevelAt(logLevel)
	}

	logger, err := config.Build()
	if err != nil {
		return nil, err
	}

	return logger, nil
}
