package gatekeeper

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"

	"github.com/majorcontext/gatekeeper/proxy"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// installRequestLogger emits one wide structured log line per request at
// completion and mirrors it onto the request's trace span.
func (s *Server) installRequestLogger() {
	s.proxy.SetLogger(func(data proxy.RequestLogData) {
		durationMS := float64(data.Duration.Nanoseconds()) / 1e6
		attrs := []slog.Attr{
			slog.String("request_id", data.RequestID),
			slog.String("http_method", data.Method),
			slog.String("http_host", data.Host),
			slog.String("http_path", data.Path),
			slog.Int("http_status", data.StatusCode),
			slog.Float64("duration_ms", durationMS),
			slog.String("proxy_type", data.RequestType),
		}
		if data.RunID != "" {
			attrs = append(attrs, slog.String("run_id", data.RunID))
		}
		if data.UserID != "" {
			attrs = append(attrs, slog.String("user_id", data.UserID))
		}
		if data.ClientAddr != "" {
			clientIP := data.ClientAddr
			if host, _, err := net.SplitHostPort(clientIP); err == nil {
				clientIP = host
			}
			attrs = append(attrs, slog.String("client_ip", clientIP))
		}
		if data.ApplicationName != "" {
			// A correlation slug the client set (e.g. via PGAPPNAME), not a
			// trusted identity — run_id, above, is the trusted identity.
			attrs = append(attrs, slog.String("application_name", data.ApplicationName))
		}
		if data.AuthInjected {
			attrs = append(attrs, slog.Bool("credential_injected", true))
			var headerNames []string
			for name := range data.InjectedHeaders {
				headerNames = append(headerNames, name)
			}
			slices.Sort(headerNames)
			attrs = append(attrs, slog.String("injected_headers", strings.Join(headerNames, ",")))
			if len(data.Grants) > 0 {
				sortedGrants := slices.Clone(data.Grants)
				slices.Sort(sortedGrants)
				attrs = append(attrs, slog.String("grants", strings.Join(sortedGrants, ",")))
			}
		}
		if data.Denied {
			attrs = append(attrs, slog.Bool("denied", true))
			attrs = append(attrs, slog.String("deny_reason", data.DenyReason))
		}
		if data.RequestSize >= 0 {
			attrs = append(attrs, slog.Int64("request_size", data.RequestSize))
		}
		if data.ResponseSize >= 0 {
			attrs = append(attrs, slog.Int64("response_size", data.ResponseSize))
		}
		if data.RequestMessages > 0 {
			attrs = append(attrs, slog.Int64("request_messages", data.RequestMessages))
		}
		if data.ResponseMessages > 0 {
			attrs = append(attrs, slog.Int64("response_messages", data.ResponseMessages))
		}
		if data.Err != nil {
			attrs = append(attrs, slog.String("error", data.Err.Error()))
		}

		var capturedHeaderAttrs []attribute.KeyValue
		for _, capture := range []struct {
			name, prefix string
			headers      http.Header
		}{
			{name: "request", prefix: "http.request.header.", headers: data.RequestHeaders},
			{name: "response", prefix: "http.response.header.", headers: data.CapturedResponseHeaders},
		} {
			configured := s.cfg.Log.CaptureRequestHeaders
			if capture.name == "response" {
				configured = s.cfg.Log.CaptureResponseHeaders
			}
			for _, header := range configured {
				values := slices.Clone(capture.headers.Values(header))
				for i := range values {
					values[i] = proxy.SanitizeLogValue(values[i])
				}
				if len(values) == 0 {
					continue
				}
				key := capture.prefix + strings.ToLower(header)
				attrs = append(attrs, slog.Any(key, values))
				capturedHeaderAttrs = append(capturedHeaderAttrs, attribute.StringSlice(key, values))
			}
		}

		level := slog.LevelInfo
		if data.Err != nil || data.StatusCode >= 500 {
			level = slog.LevelError
		} else if data.Denied || data.StatusCode >= 400 {
			level = slog.LevelWarn
		}

		logCtx := context.Background()
		if data.Ctx != nil {
			logCtx = data.Ctx
		}
		args := make([]any, len(attrs))
		for i, a := range attrs {
			args[i] = a
		}
		s.log().Log(logCtx, level, "request", args...)

		// OpenTelemetry span enrichment
		if data.Ctx != nil {
			span := trace.SpanFromContext(data.Ctx)
			if span.SpanContext().IsValid() {
				spanAttrs := []attribute.KeyValue{
					attribute.String("request_id", data.RequestID),
					attribute.Float64("duration_ms", durationMS),
					attribute.Bool("credential_injected", data.AuthInjected),
					attribute.String("proxy.request.type", data.RequestType),
					attribute.String("http.host", data.Host),
				}
				if data.RunID != "" {
					spanAttrs = append(spanAttrs, attribute.String("run_id", data.RunID))
				}
				if data.UserID != "" {
					spanAttrs = append(spanAttrs, attribute.String("user_id", data.UserID))
				}
				var headerNames []string
				for name := range data.InjectedHeaders {
					headerNames = append(headerNames, name)
				}
				slices.Sort(headerNames)
				if len(headerNames) > 0 {
					spanAttrs = append(spanAttrs, attribute.StringSlice("injected_headers", headerNames))
				}
				if len(data.Grants) > 0 {
					sortedGrants := slices.Clone(data.Grants)
					slices.Sort(sortedGrants)
					spanAttrs = append(spanAttrs, attribute.StringSlice("grants", sortedGrants))
				}
				if data.Denied {
					spanAttrs = append(spanAttrs, attribute.Bool("denied", true))
					spanAttrs = append(spanAttrs, attribute.String("deny_reason", data.DenyReason))
				}
				spanAttrs = append(spanAttrs, capturedHeaderAttrs...)
				span.AddEvent("request.complete", trace.WithAttributes(spanAttrs...))
				if data.Err != nil {
					span.RecordError(data.Err)
				}

				if data.AuthInjected {
					for name := range data.InjectedHeaders {
						proxy.RecordCredentialInjection(data.Ctx, data.Host, name)
					}
				}
			}
		}
	})
}

// installPolicyLogger logs policy denials and observations.
func (s *Server) installPolicyLogger() {
	s.proxy.SetPolicyLogger(func(data proxy.PolicyLogData) {
		// A non-blocking entry is something policy noticed and let through. It
		// is still worth surfacing — a credential bundle whose scope disagrees
		// with where its client goes shows up here — but counting it as a
		// denial would page whoever alerts on that rate for traffic nothing
		// stopped.
		msg, event := "policy denial", "policy.denial"
		level := slog.LevelWarn
		if data.NonBlocking {
			msg, event = "policy observation", "policy.observation"
			level = slog.LevelInfo
		}
		s.log().Log(context.Background(), level, msg,
			"run_id", data.RunID,
			"scope", data.Scope,
			"operation", data.Operation,
			"rule", data.Rule,
			"message", data.Message,
		)

		if data.Ctx != nil {
			span := trace.SpanFromContext(data.Ctx)
			if span.SpanContext().IsValid() {
				span.AddEvent(event, trace.WithAttributes(
					attribute.String("scope", data.Scope),
					attribute.String("operation", data.Operation),
					attribute.String("rule", data.Rule),
					attribute.String("message", data.Message),
				))
				if !data.NonBlocking {
					proxy.RecordPolicyDenial(data.Ctx, data.Scope, data.Rule)
				}
			}
		}
	})
}

func (s *Server) installLoggers() {
	s.installRequestLogger()
	s.installPolicyLogger()
}
