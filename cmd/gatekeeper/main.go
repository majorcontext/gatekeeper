package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/majorcontext/gatekeeper"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

var version = "dev"

// otelSDKDisabled reports whether the standard OTEL_SDK_DISABLED env var
// requests that the OTel SDK be disabled entirely. Per the OpenTelemetry
// spec this is a boolean env var: only a case-insensitive "true" disables
// the SDK — absent, "false", or any other value leaves it enabled.
func otelSDKDisabled(getenv func(string) string) bool {
	return strings.EqualFold(getenv("OTEL_SDK_DISABLED"), "true")
}

// logOTelError is registered as the global OTel error handler. Without it,
// SDK/export errors (e.g. no collector reachable) fall through to the OTel
// SDK's default handler, which calls the standard library "log" package.
// gatekeeper's logging setup (configureLogging in gatekeeper.go) calls
// slog.SetDefault, which per slog's documented behavior rewires the
// standard "log" package's output through the configured slog handler at
// INFO level — so every failed export attempt (once per batch interval,
// with no backoff between attempts) produced an INFO log line that drowned
// the canonical request lines whenever no collector was present. Logging
// export errors at DEBUG here keeps them observable without the noise.
//
// The record is tagged with gatekeeper.OTelDiagnosticKey so
// configureLogging's otelslog bridge filter excludes it from the OTel log
// export pipeline. Without that exclusion, a failed OTel log export
// produces this very DEBUG record, which — like any other record — gets
// fanned out to the same OTel log pipeline that just failed; it's queued,
// fails on the next export attempt, produces another diagnostic, and so on
// indefinitely while the collector stays unreachable.
func logOTelError(err error) {
	slog.Default().Debug("otel error", "error", err, gatekeeper.OTelDiagnosticKey, true)
}

func initOTel(ctx context.Context, getenv func(string) string) (shutdown func(context.Context) error, err error) {
	if otelSDKDisabled(getenv) {
		return func(context.Context) error { return nil }, nil
	}

	otel.SetErrorHandler(otel.ErrorHandlerFunc(logOTelError))

	var shutdowns []func(context.Context) error
	cleanup := func() {
		for _, fn := range shutdowns {
			fn(context.Background())
		}
	}
	defer func() {
		if err != nil {
			cleanup()
		}
	}()

	// WithFromEnv() last so OTEL_RESOURCE_ATTRIBUTES can override at deploy time.
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName("gatekeeper"),
			semconv.ServiceVersion(version),
		),
		resource.WithFromEnv(),
	)
	if err != nil {
		return nil, fmt.Errorf("creating resource: %w", err)
	}

	traceExp, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating trace exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	shutdowns = append(shutdowns, tp.Shutdown)

	metricExp, err := otlpmetrichttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating metric exporter: %w", err)
	}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp)),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(mp)
	shutdowns = append(shutdowns, mp.Shutdown)

	logExp, err := otlploghttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating log exporter: %w", err)
	}
	lp := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(logExp)),
		sdklog.WithResource(res),
	)
	global.SetLoggerProvider(lp)
	shutdowns = append(shutdowns, lp.Shutdown)

	shutdown = func(ctx context.Context) error {
		return errors.Join(
			tp.Shutdown(ctx),
			mp.Shutdown(ctx),
			lp.Shutdown(ctx),
		)
	}
	return shutdown, nil
}

func main() {
	configPath := flag.String("config", "", "path to gatekeeper.yaml")
	flag.Parse()

	if *configPath == "" {
		*configPath = os.Getenv("GATEKEEPER_CONFIG")
	}
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "error: --config or GATEKEEPER_CONFIG required")
		os.Exit(1)
	}

	cfg, err := gatekeeper.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	otelShutdown, err := initOTel(ctx, os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error initializing otel: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := otelShutdown(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "error shutting down otel: %v\n", err)
		}
	}()

	srv, err := gatekeeper.New(ctx, cfg, version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating server: %v\n", err)
		os.Exit(1)
	}

	if err := srv.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
