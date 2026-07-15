package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/majorcontext/gatekeeper"
)

// TestOtelSDKDisabled pins the OTEL_SDK_DISABLED semantics: per the
// OpenTelemetry spec this is a boolean env var where only a case-insensitive
// "true" disables the SDK. Absent, "false", and any other garbage value
// leave it enabled.
func TestOtelSDKDisabled(t *testing.T) {
	tests := []struct {
		name string
		val  string
		set  bool
		want bool
	}{
		{name: "absent", set: false, want: false},
		{name: "empty", val: "", set: true, want: false},
		{name: "true lowercase", val: "true", set: true, want: true},
		{name: "TRUE uppercase", val: "TRUE", set: true, want: true},
		{name: "True mixed case", val: "True", set: true, want: true},
		{name: "false", val: "false", set: true, want: false},
		{name: "garbage", val: "yes", set: true, want: false},
		{name: "numeric one", val: "1", set: true, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getenv := func(key string) string {
				if key != "OTEL_SDK_DISABLED" {
					t.Fatalf("unexpected env lookup: %q", key)
				}
				if !tt.set {
					return ""
				}
				return tt.val
			}
			if got := otelSDKDisabled(getenv); got != tt.want {
				t.Errorf("otelSDKDisabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestLogOTelError_DemotesToDebug encodes the incident: running gatekeeper
// without a collector produced one INFO line per second like
//
//	{"level":"INFO","msg":"Post \"https://localhost:4318/v1/logs\": dial tcp [::1]:4318: connect: connection refused"}
//
// because the OTel SDK's default global error handler routes export
// failures through the standard "log" package, which slog.SetDefault
// rewires to the configured slog handler at INFO level. logOTelError is
// registered as the OTel error handler instead, and must log at DEBUG so it
// doesn't drown the canonical request lines at the default "info" log
// level, while still being observable when debug logging is enabled.
func TestLogOTelError_DemotesToDebug(t *testing.T) {
	sampleErr := errors.New(`Post "https://localhost:4318/v1/logs": dial tcp [::1]:4318: connect: connection refused`)

	t.Run("invisible at info level", func(t *testing.T) {
		var buf bytes.Buffer
		prev := slog.Default()
		t.Cleanup(func() { slog.SetDefault(prev) })
		slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))

		logOTelError(sampleErr)

		if got := buf.String(); got != "" {
			t.Errorf("logOTelError logged at info level, want nothing; got %q", got)
		}
	})

	t.Run("visible at debug level", func(t *testing.T) {
		var buf bytes.Buffer
		prev := slog.Default()
		t.Cleanup(func() { slog.SetDefault(prev) })
		slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

		logOTelError(sampleErr)

		got := buf.String()
		if !bytes.Contains(buf.Bytes(), []byte(`"level":"DEBUG"`)) {
			t.Errorf("logOTelError did not log at DEBUG level; got %q", got)
		}
		if !bytes.Contains(buf.Bytes(), []byte("connection refused")) {
			t.Errorf("logOTelError did not include the underlying error; got %q", got)
		}
	})
}

// recordingHandler is a minimal slog.Handler that captures every record
// passed to it, for inspecting the attributes a call site attached.
type recordingHandler struct {
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

// TestLogOTelError_MarksAsOTelDiagnostic encodes the fix for #48: gatekeeper.go's
// configureLogging fans every slog record out to the otelslog bridge
// unconditionally, so logOTelError's own DEBUG record on a failed OTel
// export was itself re-enqueued into the same failing OTel log-export
// pipeline — failed export -> DEBUG diagnostic -> re-enqueued -> next
// export fails carrying it -> another diagnostic, indefinitely while the
// collector is unreachable. logOTelError must mark its record with
// gatekeeper.OTelDiagnosticKey so configureLogging's bridge filter can keep
// it out of that pipeline.
func TestLogOTelError_MarksAsOTelDiagnostic(t *testing.T) {
	var handler recordingHandler
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	slog.SetDefault(slog.New(&handler))

	logOTelError(errors.New(`Post "https://localhost:4318/v1/logs": dial tcp [::1]:4318: connect: connection refused`))

	if len(handler.records) != 1 {
		t.Fatalf("got %d records, want 1", len(handler.records))
	}

	marked := false
	handler.records[0].Attrs(func(a slog.Attr) bool {
		if a.Key == gatekeeper.OTelDiagnosticKey && a.Value.Kind() == slog.KindBool && a.Value.Bool() {
			marked = true
			return false
		}
		return true
	})
	if !marked {
		t.Errorf("logOTelError record missing %s=true attribute, so configureLogging's bridge filter can't exclude it from the OTel log-export pipeline", gatekeeper.OTelDiagnosticKey)
	}
}
