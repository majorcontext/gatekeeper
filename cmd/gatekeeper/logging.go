package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/majorcontext/gatekeeper"

	"go.opentelemetry.io/contrib/bridges/otelslog"
)

// newLogger builds the process logger from the log config. The returned
// cleanup closes the log file when the output is a file path.
func newLogger(cfg gatekeeper.LogConfig) (*slog.Logger, func(), error) {
	var level slog.Level
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	var (
		w       *os.File
		cleanup = func() {}
	)
	switch strings.ToLower(cfg.Output) {
	case "", "stderr":
		w = os.Stderr
	case "stdout":
		w = os.Stdout
	default:
		f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("opening log output %q: %w", cfg.Output, err)
		}
		w = f
		cleanup = func() { f.Close() }
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if strings.ToLower(cfg.Format) == "json" {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}
	handler = newMultiHandler(handler, newOTelDiagnosticFilter(otelslog.NewHandler("gatekeeper")))
	return slog.New(handler), cleanup, nil
}

// otelDiagnosticKey marks a record about the OTel pipeline itself. The
// otelslog bridge drops it: a failed log export would otherwise log a
// diagnostic that is exported, fails, and logs again. The console and file
// handlers still receive it.
const otelDiagnosticKey = "otel_diagnostic"

// otelDiagnosticFilter wraps a slog.Handler — the otelslog bridge — and
// drops any record carrying otelDiagnosticKey before it reaches the wrapped
// handler, keeping gatekeeper's own OTel diagnostics out of the OTel log
// export pipeline. Records without the marker pass through unchanged.
type otelDiagnosticFilter struct {
	slog.Handler
}

func newOTelDiagnosticFilter(h slog.Handler) slog.Handler {
	return &otelDiagnosticFilter{Handler: h}
}

func (f *otelDiagnosticFilter) Handle(ctx context.Context, record slog.Record) error {
	marked := false
	record.Attrs(func(a slog.Attr) bool {
		if a.Key == otelDiagnosticKey && a.Value.Kind() == slog.KindBool && a.Value.Bool() {
			marked = true
			return false
		}
		return true
	})
	if marked {
		return nil
	}
	return f.Handler.Handle(ctx, record)
}

func (f *otelDiagnosticFilter) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &otelDiagnosticFilter{Handler: f.Handler.WithAttrs(attrs)}
}

func (f *otelDiagnosticFilter) WithGroup(name string) slog.Handler {
	return &otelDiagnosticFilter{Handler: f.Handler.WithGroup(name)}
}

// multiHandler fans out log records to multiple slog handlers.
type multiHandler struct {
	handlers []slog.Handler
}

func newMultiHandler(handlers ...slog.Handler) *multiHandler {
	return &multiHandler{handlers: handlers}
}

func (m *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m *multiHandler) Handle(ctx context.Context, record slog.Record) error {
	var errs []error
	for _, h := range m.handlers {
		if h.Enabled(ctx, record.Level) {
			if err := h.Handle(ctx, record); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		handlers[i] = h.WithAttrs(attrs)
	}
	return &multiHandler{handlers: handlers}
}

func (m *multiHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		handlers[i] = h.WithGroup(name)
	}
	return &multiHandler{handlers: handlers}
}
