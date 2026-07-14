package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	keeplib "github.com/majorcontext/keep"
)

// TestMCPRelay_NilCredentialStore tests that handleMCPRelay fails gracefully
// when credStore is nil and no RunContextData is present.
func TestMCPRelay_NilCredentialStore(t *testing.T) {
	// Create proxy without credential store (nil) and no context resolver.
	// This simulates a misconfigured proxy where neither daemon-mode
	// RunContextData nor a legacy credStore provides credentials.
	p := &Proxy{
		credStore: nil,
		mcpServers: []MCPServerConfig{
			{
				Name: "context7",
				URL:  "https://mcp.context7.com/mcp",
				Auth: &MCPAuthConfig{
					Grant:  "mcp-context7",
					Header: "API_KEY",
				},
			},
		},
	}

	// Create test request to MCP relay endpoint
	req := httptest.NewRequest("POST", "/mcp/context7/v1/endpoint", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	p.handleMCPRelay(rec, req)

	// Should fail gracefully with 500 and helpful error message
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Failed to load credential") {
		t.Errorf("error message should mention failed credential load, got: %s", body)
	}
}

// TestMCPRelay_DaemonModeCredentials tests that handleMCPRelay resolves
// credentials from RunContextData when credStore is nil (daemon mode).
func TestMCPRelay_DaemonModeCredentials(t *testing.T) {
	// Mock backend that records the received header.
	var receivedKey string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey = r.Header.Get("X-Api-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p := &Proxy{
		credStore: nil, // No store — daemon mode
		mcpServers: []MCPServerConfig{
			{
				Name: "test-server",
				URL:  backend.URL,
				Auth: &MCPAuthConfig{
					Grant:  "mcp-test",
					Header: "X-Api-Key",
				},
			},
		},
	}

	// Build request with RunContextData carrying the credential and MCP config.
	req := httptest.NewRequest("GET", "/mcp/test-server", nil)
	rc := &RunContextData{
		Credentials: map[string][]credentialHeader{
			"example.com": {{Name: "X-Api-Key", Value: "real-secret", Grant: "mcp-test"}},
		},
		MCPServers: []MCPServerConfig{
			{
				Name: "test-server",
				URL:  backend.URL,
				Auth: &MCPAuthConfig{
					Grant:  "mcp-test",
					Header: "X-Api-Key",
				},
			},
		},
	}
	ctx := context.WithValue(req.Context(), runContextKey, rc)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	p.handleMCPRelay(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if receivedKey != "real-secret" {
		t.Errorf("backend received X-Api-Key = %q, want %q", receivedKey, "real-secret")
	}
}

// TestMCPRelay_MissingCredential tests that handleMCPRelay provides helpful
// error when credential is not stored.
func TestMCPRelay_MissingCredential(t *testing.T) {
	// Create proxy with empty credential store
	mockStore := &mockCredentialStore{
		tokens: map[string]string{},
	}

	p := &Proxy{
		credStore: mockStore,
		mcpServers: []MCPServerConfig{
			{
				Name: "context7",
				URL:  "https://mcp.context7.com/mcp",
				Auth: &MCPAuthConfig{
					Grant:  "mcp-context7",
					Header: "API_KEY",
				},
			},
		},
	}

	req := httptest.NewRequest("POST", "/mcp/context7", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	p.handleMCPRelay(rec, req)

	// Should fail with helpful error
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Failed to load credential") {
		t.Errorf("error should mention failed to load credential, got: %s", body)
	}
	if !strings.Contains(body, "moat grant mcp context7") {
		t.Errorf("error should suggest grant command, got: %s", body)
	}
}

// TestMCPRelay_PathHandling tests various path edge cases to prevent
// regressions in URL path handling.
func TestMCPRelay_PathHandling(t *testing.T) {
	tests := []struct {
		name             string
		serverPathSuffix string
		requestPath      string
		expectedPath     string
		expectedQuery    string
	}{
		{
			name:             "root path",
			serverPathSuffix: "/api",
			requestPath:      "/mcp/test",
			expectedPath:     "/api",
			expectedQuery:    "",
		},
		{
			name:             "trailing slash on server URL",
			serverPathSuffix: "/api/",
			requestPath:      "/mcp/test",
			expectedPath:     "/api/",
			expectedQuery:    "",
		},
		{
			name:             "nested path",
			serverPathSuffix: "/api",
			requestPath:      "/mcp/test/v1/endpoint",
			expectedPath:     "/api/v1/endpoint",
			expectedQuery:    "",
		},
		{
			name:             "nested path with trailing slash",
			serverPathSuffix: "/api/",
			requestPath:      "/mcp/test/v1/endpoint",
			expectedPath:     "/api/v1/endpoint",
			expectedQuery:    "",
		},
		{
			name:             "query parameters",
			serverPathSuffix: "/api",
			requestPath:      "/mcp/test/v1/endpoint?param=value&other=123",
			expectedPath:     "/api/v1/endpoint",
			expectedQuery:    "param=value&other=123",
		},
		{
			name:             "slash after server name",
			serverPathSuffix: "/api",
			requestPath:      "/mcp/test/",
			expectedPath:     "/api", // "/" is skipped by the handler
			expectedQuery:    "",
		},
		{
			name:             "empty path after server name",
			serverPathSuffix: "/api",
			requestPath:      "/mcp/test",
			expectedPath:     "/api",
			expectedQuery:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock backend that records the request path
			var receivedPath, receivedQuery string
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedPath = r.URL.Path
				receivedQuery = r.URL.RawQuery
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			}))
			defer backend.Close()

			mockStore := &mockCredentialStore{
				tokens: map[string]string{},
			}

			p := &Proxy{
				credStore: mockStore,
				mcpServers: []MCPServerConfig{
					{
						Name: "test",
						URL:  backend.URL + tt.serverPathSuffix,
						Auth: nil, // No auth for simplicity
					},
				},
			}

			req := httptest.NewRequest("GET", tt.requestPath, nil)
			rec := httptest.NewRecorder()
			p.handleMCPRelay(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
			}

			if receivedPath != tt.expectedPath {
				t.Errorf("path = %q, want %q", receivedPath, tt.expectedPath)
			}

			if receivedQuery != tt.expectedQuery {
				t.Errorf("query = %q, want %q", receivedQuery, tt.expectedQuery)
			}
		})
	}
}

// TestMCPRelay_ServerNotFound tests error handling for non-existent MCP servers.
func TestMCPRelay_ServerNotFound(t *testing.T) {
	p := &Proxy{
		credStore:  &mockCredentialStore{tokens: map[string]string{}},
		mcpServers: []MCPServerConfig{},
	}

	req := httptest.NewRequest("POST", "/mcp/nonexistent", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	p.handleMCPRelay(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "not configured") {
		t.Errorf("error should mention server not configured, got: %s", body)
	}
	if !strings.Contains(body, "nonexistent") {
		t.Errorf("error should include server name, got: %s", body)
	}
}

// TestMCPRelay_LogsAllExitPaths verifies that handleMCPRelay emits a canonical
// log line (via p.logRequest, RequestType "mcp") on every client/config-error
// exit path, not just on upstream-connect-failure and success. These are not
// policy decisions, so Denied must stay false.
func TestMCPRelay_LogsAllExitPaths(t *testing.T) {
	t.Run("unconfigured server (404)", func(t *testing.T) {
		p := &Proxy{
			credStore:  &mockCredentialStore{tokens: map[string]string{}},
			mcpServers: []MCPServerConfig{},
		}

		var mu sync.Mutex
		var logged []RequestLogData
		p.SetLogger(func(data RequestLogData) {
			mu.Lock()
			defer mu.Unlock()
			logged = append(logged, data)
		})

		req := httptest.NewRequest("POST", "/mcp/nonexistent", strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		p.handleMCPRelay(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
		}

		mu.Lock()
		defer mu.Unlock()
		if len(logged) != 1 {
			t.Fatalf("logged %d entries, want exactly 1: %+v", len(logged), logged)
		}
		data := logged[0]
		if data.RequestType != "mcp" {
			t.Errorf("RequestType = %q, want %q", data.RequestType, "mcp")
		}
		if data.StatusCode != http.StatusNotFound {
			t.Errorf("StatusCode = %d, want %d", data.StatusCode, http.StatusNotFound)
		}
		if data.ClientAddr == "" {
			t.Error("ClientAddr should not be empty")
		}
		if data.Denied {
			t.Error("Denied should be false — this is a client/config error, not a policy decision")
		}
	})

	t.Run("invalid server URL (500)", func(t *testing.T) {
		p := &Proxy{
			credStore: &mockCredentialStore{tokens: map[string]string{}},
			mcpServers: []MCPServerConfig{
				{Name: "bad", URL: "://invalid-url", Auth: nil},
			},
		}

		var mu sync.Mutex
		var logged []RequestLogData
		p.SetLogger(func(data RequestLogData) {
			mu.Lock()
			defer mu.Unlock()
			logged = append(logged, data)
		})

		req := httptest.NewRequest("POST", "/mcp/bad", strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		p.handleMCPRelay(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
		}

		mu.Lock()
		defer mu.Unlock()
		if len(logged) != 1 {
			t.Fatalf("logged %d entries, want exactly 1: %+v", len(logged), logged)
		}
		data := logged[0]
		if data.RequestType != "mcp" {
			t.Errorf("RequestType = %q, want %q", data.RequestType, "mcp")
		}
		if data.StatusCode != http.StatusInternalServerError {
			t.Errorf("StatusCode = %d, want %d", data.StatusCode, http.StatusInternalServerError)
		}
		if data.ClientAddr == "" {
			t.Error("ClientAddr should not be empty")
		}
		if data.Denied {
			t.Error("Denied should be false — this is a client/config error, not a policy decision")
		}
		if data.Err == nil {
			t.Error("Err should be set to the URL parse error")
		}
	})

	t.Run("missing credential (500)", func(t *testing.T) {
		p := &Proxy{
			credStore: &mockCredentialStore{tokens: map[string]string{}},
			mcpServers: []MCPServerConfig{
				{
					Name: "context7",
					URL:  "https://mcp.context7.com/mcp",
					Auth: &MCPAuthConfig{Grant: "mcp-context7", Header: "API_KEY"},
				},
			},
		}

		var mu sync.Mutex
		var logged []RequestLogData
		p.SetLogger(func(data RequestLogData) {
			mu.Lock()
			defer mu.Unlock()
			logged = append(logged, data)
		})

		req := httptest.NewRequest("POST", "/mcp/context7", strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		p.handleMCPRelay(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
		}

		mu.Lock()
		defer mu.Unlock()
		if len(logged) != 1 {
			t.Fatalf("logged %d entries, want exactly 1: %+v", len(logged), logged)
		}
		data := logged[0]
		if data.RequestType != "mcp" {
			t.Errorf("RequestType = %q, want %q", data.RequestType, "mcp")
		}
		if data.StatusCode != http.StatusInternalServerError {
			t.Errorf("StatusCode = %d, want %d", data.StatusCode, http.StatusInternalServerError)
		}
		if data.ClientAddr == "" {
			t.Error("ClientAddr should not be empty")
		}
		if data.Denied {
			t.Error("Denied should be false — this is a client/config error, not a policy decision")
		}
	})

	t.Run("request construction failure (500)", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer backend.Close()

		p := &Proxy{
			credStore: &mockCredentialStore{tokens: map[string]string{}},
			mcpServers: []MCPServerConfig{
				{Name: "test", URL: backend.URL, Auth: nil},
			},
		}

		var mu sync.Mutex
		var logged []RequestLogData
		p.SetLogger(func(data RequestLogData) {
			mu.Lock()
			defer mu.Unlock()
			logged = append(logged, data)
		})

		req := httptest.NewRequest("POST", "/mcp/test", strings.NewReader("{}"))
		// An invalid HTTP method (containing a space) makes
		// http.NewRequestWithContext fail when building the upstream request.
		req.Method = "BAD METHOD"
		rec := httptest.NewRecorder()
		p.handleMCPRelay(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
		}

		mu.Lock()
		defer mu.Unlock()
		if len(logged) != 1 {
			t.Fatalf("logged %d entries, want exactly 1: %+v", len(logged), logged)
		}
		data := logged[0]
		if data.RequestType != "mcp" {
			t.Errorf("RequestType = %q, want %q", data.RequestType, "mcp")
		}
		if data.StatusCode != http.StatusInternalServerError {
			t.Errorf("StatusCode = %d, want %d", data.StatusCode, http.StatusInternalServerError)
		}
		if data.ClientAddr == "" {
			t.Error("ClientAddr should not be empty")
		}
		if data.Denied {
			t.Error("Denied should be false — this is a client/config error, not a policy decision")
		}
		if data.Err == nil {
			t.Error("Err should be set to the request construction error")
		}
	})
}

// TestMCPRelay_HeaderInjection verifies that credentials are injected as headers.
func TestMCPRelay_HeaderInjection(t *testing.T) {
	var receivedHeader string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-API-Key")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backend.Close()

	mockStore := &mockCredentialStore{
		tokens: map[string]string{
			"mcp-test": "secret-token-123",
		},
	}

	p := &Proxy{
		credStore: mockStore,
		mcpServers: []MCPServerConfig{
			{
				Name: "test",
				URL:  backend.URL,
				Auth: &MCPAuthConfig{
					Grant:  "mcp-test",
					Header: "X-API-Key",
				},
			},
		},
	}

	req := httptest.NewRequest("POST", "/mcp/test/v1/endpoint", strings.NewReader(`{"test":true}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	p.handleMCPRelay(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	if receivedHeader != "secret-token-123" {
		t.Errorf("received header = %q, want %q", receivedHeader, "secret-token-123")
	}
}

// TestMCPRelay_SSEStreaming verifies that SSE (Server-Sent Events) responses
// are properly streamed with flushing.
func TestMCPRelay_SSEStreaming(t *testing.T) {
	// Create a backend that sends SSE events
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)

		// Send SSE events
		w.Write([]byte("data: event1\n\n"))
		w.Write([]byte("data: event2\n\n"))
	}))
	defer backend.Close()

	mockStore := &mockCredentialStore{
		tokens: map[string]string{},
	}

	p := &Proxy{
		credStore: mockStore,
		mcpServers: []MCPServerConfig{
			{
				Name: "sse-test",
				URL:  backend.URL,
				Auth: nil,
			},
		},
	}

	req := httptest.NewRequest("GET", "/mcp/sse-test", nil)
	rec := httptest.NewRecorder()
	p.handleMCPRelay(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Verify SSE headers are preserved
	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/event-stream")
	}

	// Verify body contains SSE events
	body := rec.Body.String()
	if !strings.Contains(body, "data: event1") {
		t.Errorf("body should contain event1, got: %s", body)
	}
	if !strings.Contains(body, "data: event2") {
		t.Errorf("body should contain event2, got: %s", body)
	}
}

// TestMCPRelay_RequestBodyPreserved verifies that request bodies are
// properly forwarded to the MCP server.
func TestMCPRelay_RequestBodyPreserved(t *testing.T) {
	var receivedBody string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		receivedBody = string(bodyBytes)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	mockStore := &mockCredentialStore{
		tokens: map[string]string{},
	}

	p := &Proxy{
		credStore: mockStore,
		mcpServers: []MCPServerConfig{
			{
				Name: "test",
				URL:  backend.URL,
				Auth: nil,
			},
		},
	}

	requestBody := `{"method":"test","params":{"key":"value"}}`
	req := httptest.NewRequest("POST", "/mcp/test", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	p.handleMCPRelay(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	if receivedBody != requestBody {
		t.Errorf("body = %q, want %q", receivedBody, requestBody)
	}
}

// TestMCPRelay_ProxyHeadersFiltered verifies that proxy-specific headers
// are not forwarded to the MCP server.
func TestMCPRelay_ProxyHeadersFiltered(t *testing.T) {
	var receivedHeaders http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	mockStore := &mockCredentialStore{
		tokens: map[string]string{},
	}

	p := &Proxy{
		credStore: mockStore,
		mcpServers: []MCPServerConfig{
			{
				Name: "test",
				URL:  backend.URL,
				Auth: nil,
			},
		},
	}

	req := httptest.NewRequest("POST", "/mcp/test", strings.NewReader("{}"))
	req.Header.Set("Proxy-Authorization", "Basic secret")
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Custom-Header", "custom-value")

	rec := httptest.NewRecorder()
	p.handleMCPRelay(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Proxy headers should be filtered out
	if receivedHeaders.Get("Proxy-Authorization") != "" {
		t.Error("Proxy-Authorization should be filtered out")
	}
	if receivedHeaders.Get("Proxy-Connection") != "" {
		t.Error("Proxy-Connection should be filtered out")
	}

	// Other headers should be preserved
	if receivedHeaders.Get("Content-Type") != "application/json" {
		t.Error("Content-Type should be preserved")
	}
	if receivedHeaders.Get("X-Custom-Header") != "custom-value" {
		t.Error("X-Custom-Header should be preserved")
	}
}

// TestMCPRelay_InvalidServerURL tests error handling for malformed MCP server URLs.
func TestMCPRelay_InvalidServerURL(t *testing.T) {
	p := &Proxy{
		credStore: &mockCredentialStore{tokens: map[string]string{}},
		mcpServers: []MCPServerConfig{
			{
				Name: "bad",
				URL:  "://invalid-url",
				Auth: nil,
			},
		},
	}

	req := httptest.NewRequest("POST", "/mcp/bad", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	p.handleMCPRelay(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Invalid MCP server URL") {
		t.Errorf("error should mention invalid URL, got: %s", body)
	}
}

// TestMCPRelay_NoAuth tests MCP servers without authentication.
func TestMCPRelay_NoAuth(t *testing.T) {
	var receivedAuthHeader string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backend.Close()

	p := &Proxy{
		credStore: &mockCredentialStore{tokens: map[string]string{}},
		mcpServers: []MCPServerConfig{
			{
				Name: "public",
				URL:  backend.URL,
				Auth: nil, // No authentication
			},
		},
	}

	req := httptest.NewRequest("POST", "/mcp/public", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	p.handleMCPRelay(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// Should not inject any auth header
	if receivedAuthHeader != "" {
		t.Errorf("auth header should be empty, got: %q", receivedAuthHeader)
	}
}

// TestServeHTTP_DirectMCPRelay tests that ServeHTTP routes direct /mcp/{token}/{name}
// requests through handleDirectMCPRelay, bypassing proxy auth.
func TestServeHTTP_DirectMCPRelay(t *testing.T) {
	var receivedKey string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey = r.Header.Get("X-Api-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p := NewProxy()
	token := "test-run-token-abc"

	// Set up context resolver (daemon mode) that recognizes our token.
	p.SetContextResolver(func(t string) (*RunContextData, bool) {
		if t != token {
			return nil, false
		}
		return &RunContextData{
			RunID: "run-1",
			Credentials: map[string][]credentialHeader{
				backend.Listener.Addr().String(): {{Name: "X-Api-Key", Value: "real-secret", Grant: "mcp-test"}},
			},
			MCPServers: []MCPServerConfig{
				{
					Name: "my-server",
					URL:  backend.URL,
					Auth: &MCPAuthConfig{Grant: "mcp-test", Header: "X-Api-Key"},
				},
			},
		}, true
	})

	// Direct request (r.URL.Host empty) with token in URL path.
	req := httptest.NewRequest("POST", "/mcp/"+token+"/my-server", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if receivedKey != "real-secret" {
		t.Errorf("backend received X-Api-Key = %q, want %q", receivedKey, "real-secret")
	}
}

// TestServeHTTP_DirectMCPRelay_InvalidToken tests that an invalid token returns 407.
func TestServeHTTP_DirectMCPRelay_InvalidToken(t *testing.T) {
	p := NewProxy()
	p.SetContextResolver(func(string) (*RunContextData, bool) {
		return nil, false
	})

	req := httptest.NewRequest("POST", "/mcp/bad-token/my-server", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Basic realm="gatekeeper"` {
		t.Errorf("WWW-Authenticate = %q, want %q", got, `Basic realm="gatekeeper"`)
	}
}

// TestServeHTTP_DirectAWSCredentials tests that ServeHTTP routes direct /_aws/credentials
// requests through handleDirectAWSCredentials, extracting the token from Authorization.
func TestServeHTTP_DirectAWSCredentials(t *testing.T) {
	p := NewProxy()
	token := "aws-run-token-xyz"

	// Create a mock AWS handler that returns a fixed credential response.
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Version":1,"AccessKeyId":"AKIA..."}`))
	})

	p.SetContextResolver(func(t string) (*RunContextData, bool) {
		if t != token {
			return nil, false
		}
		return &RunContextData{
			RunID:      "run-aws",
			AWSHandler: mockHandler,
		}, true
	})

	// Direct request with Authorization: Bearer {token}.
	req := httptest.NewRequest("GET", "/_aws/credentials", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "AKIA") {
		t.Errorf("expected AWS credential response, got: %s", rec.Body.String())
	}
}

// TestServeHTTP_DirectAWSCredentials_NoAuth tests that missing auth returns 401.
func TestServeHTTP_DirectAWSCredentials_NoAuth(t *testing.T) {
	p := NewProxy()
	p.SetContextResolver(func(string) (*RunContextData, bool) {
		return nil, false
	})

	req := httptest.NewRequest("GET", "/_aws/credentials", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// TestMCPRelay_LogsCredentialInjection verifies that the canonical log line
// for a successful MCP relay call records the injected credential — an
// authenticated MCP call must not look unauthenticated in the audit trail.
func TestMCPRelay_LogsCredentialInjection(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer backend.Close()

	mockStore := &mockCredentialStore{
		tokens: map[string]string{
			"mcp-test": "secret-token-123",
		},
	}

	p := &Proxy{
		credStore: mockStore,
		mcpServers: []MCPServerConfig{
			{
				Name: "test",
				URL:  backend.URL,
				Auth: &MCPAuthConfig{
					Grant:  "mcp-test",
					Header: "X-API-Key",
				},
			},
		},
	}

	var mu sync.Mutex
	var logged []RequestLogData
	p.SetLogger(func(data RequestLogData) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, data)
	})

	req := httptest.NewRequest("POST", "/mcp/test", strings.NewReader(`{"test":true}`))
	rec := httptest.NewRecorder()
	p.handleMCPRelay(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(logged) != 1 {
		t.Fatalf("logged %d entries, want exactly 1: %+v", len(logged), logged)
	}
	data := logged[0]
	if !data.AuthInjected {
		t.Error("AuthInjected = false, want true — a credential was injected for this MCP call")
	}
	if !data.InjectedHeaders["x-api-key"] {
		t.Errorf("InjectedHeaders = %v, want to contain %q", data.InjectedHeaders, "x-api-key")
	}
}

// TestMCPRelay_CopyErrorLogsErr verifies that when streaming the MCP response
// body to the client fails partway through, the canonical log line records
// the error instead of reporting a clean 200.
func TestMCPRelay_CopyErrorLogsErr(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial-data"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic(http.ErrAbortHandler)
	}))
	defer backend.Close()

	p := &Proxy{
		credStore: &mockCredentialStore{tokens: map[string]string{}},
		mcpServers: []MCPServerConfig{
			{Name: "test", URL: backend.URL, Auth: nil},
		},
	}

	var mu sync.Mutex
	var logged []RequestLogData
	p.SetLogger(func(data RequestLogData) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, data)
	})

	req := httptest.NewRequest("POST", "/mcp/test", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	p.handleMCPRelay(rec, req)

	mu.Lock()
	defer mu.Unlock()
	if len(logged) != 1 {
		t.Fatalf("logged %d entries, want exactly 1: %+v", len(logged), logged)
	}
	data := logged[0]
	if data.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d (headers were already sent)", data.StatusCode, http.StatusOK)
	}
	if data.Err == nil {
		t.Error("Err is nil, want the mid-stream copy error to be recorded")
	}
}

// TestMCPRelay_ClientCancelDoesNotSetErr verifies that when the client
// cancels the request context mid-stream, the resulting upstream read
// failure is NOT recorded as Err — a client hanging up is a routine
// disconnect, not a proxy-side failure, and must not escalate the canonical
// log line to ERROR severity. Mirrors TestRelay_ClientCancelDoesNotSetErr
// for the MCP relay path.
func TestMCPRelay_ClientCancelDoesNotSetErr(t *testing.T) {
	firstByteSent := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial-data"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		close(firstByteSent)
		// httptest.Server.Close (deferred below) waits for this handler to
		// return, so keep the sleep short to keep the test fast.
		time.Sleep(300 * time.Millisecond)
	}))
	defer backend.Close()

	p := &Proxy{
		credStore:  &mockCredentialStore{tokens: map[string]string{}},
		mcpServers: []MCPServerConfig{{Name: "test", URL: backend.URL, Auth: nil}},
	}

	var mu sync.Mutex
	var logged []RequestLogData
	p.SetLogger(func(data RequestLogData) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, data)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest("POST", "/mcp/test", strings.NewReader("{}")).WithContext(ctx)
	rec := httptest.NewRecorder()

	go func() {
		<-firstByteSent
		// Give mcpRelayClient.Do time to return with the response headers
		// already read, so the cancellation lands in the streaming copy
		// loop below rather than racing the initial round trip itself.
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	p.handleMCPRelay(rec, req)

	mu.Lock()
	defer mu.Unlock()
	if len(logged) != 1 {
		t.Fatalf("logged %d entries, want exactly 1: %+v", len(logged), logged)
	}
	data := logged[0]
	if data.Err != nil {
		t.Errorf("Err = %v, want nil — the client canceled the request, this is a routine disconnect", data.Err)
	}
}

// mcpDenyAllRules is a Keep rule file loaded under the "mcp-keep-test" scope
// (matching the "mcp-" + serverName key handleMCPRelay looks up) that denies
// every tool call unconditionally.
const mcpDenyAllRules = `
scope: mcp-keep-test
mode: enforce
rules:
  - name: deny-all-tools
    match:
      operation: "*"
    action: deny
    message: "no tools allowed by policy"
`

// mcpRedactSecretRules is a Keep rule file loaded under the "mcp-keep-test"
// scope that redacts an AWS-key-shaped secret from any tool call's
// arguments, forcing a Redact decision (rather than Deny) in
// handleMCPRelay's Keep-policy block.
const mcpRedactSecretRules = `
scope: mcp-keep-test
mode: enforce
rules:
  - name: redact-secret
    match:
      operation: "*"
    action: redact
    redact:
      target: "params.secret"
      patterns:
        - match: "AKIA[0-9A-Z]{16}"
          replace: "[REDACTED:AWS_KEY]"
`

// errReader is an io.Reader that always fails, used to force the
// io.ReadAll(r.Body) failure path in handleMCPRelay's Keep-policy block.
type errReader struct{}

func (errReader) Read(p []byte) (int, error) {
	return 0, errors.New("simulated body read failure")
}

// TestMCPRelay_KeepPolicyLogsCanonicalLine verifies that every exit in
// handleMCPRelay's Keep-policy block (read-body failure, fail-closed invalid
// JSON, and policy-deny) emits a canonical log line via p.logRequest, not
// just the logPolicy-only treatment it had before. This is the Keep-block
// counterpart to TestMCPRelay_LogsAllExitPaths, which covers the plain
// (non-policy) exit paths.
func TestMCPRelay_KeepPolicyLogsCanonicalLine(t *testing.T) {
	newEngine := func(t *testing.T) *keeplib.Engine {
		t.Helper()
		eng, err := keeplib.LoadFromBytes([]byte(mcpDenyAllRules))
		if err != nil {
			t.Fatalf("LoadFromBytes: %v", err)
		}
		t.Cleanup(func() { eng.Close() })
		return eng
	}

	t.Run("read-body failure (500)", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer backend.Close()

		eng := newEngine(t)
		p := &Proxy{
			credStore: &mockCredentialStore{tokens: map[string]string{}},
			mcpServers: []MCPServerConfig{
				{Name: "keep-test", URL: backend.URL, Auth: nil},
			},
		}

		var mu sync.Mutex
		var logged []RequestLogData
		p.SetLogger(func(data RequestLogData) {
			mu.Lock()
			defer mu.Unlock()
			logged = append(logged, data)
		})

		req := httptest.NewRequest(http.MethodPost, "/mcp/keep-test", errReader{})
		rc := &RunContextData{
			KeepEngines: map[string]*keeplib.Engine{"mcp-keep-test": eng},
			MCPServers:  p.mcpServers,
		}
		req = req.WithContext(context.WithValue(req.Context(), runContextKey, rc))

		rec := httptest.NewRecorder()
		p.handleMCPRelay(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
		}

		mu.Lock()
		defer mu.Unlock()
		if len(logged) != 1 {
			t.Fatalf("logged %d entries, want exactly 1: %+v", len(logged), logged)
		}
		data := logged[0]
		if data.StatusCode != http.StatusInternalServerError {
			t.Errorf("StatusCode = %d, want %d", data.StatusCode, http.StatusInternalServerError)
		}
		if data.ClientAddr == "" {
			t.Error("ClientAddr should not be empty")
		}
		if data.Err == nil {
			t.Error("Err should be set to the body-read error")
		}
	})

	t.Run("invalid JSON fail-closed (403)", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer backend.Close()

		eng := newEngine(t)
		p := &Proxy{
			credStore: &mockCredentialStore{tokens: map[string]string{}},
			mcpServers: []MCPServerConfig{
				{Name: "keep-test", URL: backend.URL, Auth: nil},
			},
		}

		var mu sync.Mutex
		var logged []RequestLogData
		p.SetLogger(func(data RequestLogData) {
			mu.Lock()
			defer mu.Unlock()
			logged = append(logged, data)
		})

		req := httptest.NewRequest(http.MethodPost, "/mcp/keep-test", strings.NewReader("not json"))
		rc := &RunContextData{
			KeepEngines: map[string]*keeplib.Engine{"mcp-keep-test": eng},
			MCPServers:  p.mcpServers,
		}
		req = req.WithContext(context.WithValue(req.Context(), runContextKey, rc))

		rec := httptest.NewRecorder()
		p.handleMCPRelay(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
		}

		mu.Lock()
		defer mu.Unlock()
		if len(logged) != 1 {
			t.Fatalf("logged %d entries, want exactly 1: %+v", len(logged), logged)
		}
		data := logged[0]
		if data.StatusCode != http.StatusForbidden {
			t.Errorf("StatusCode = %d, want %d", data.StatusCode, http.StatusForbidden)
		}
		if !data.Denied {
			t.Error("Denied should be true — invalid JSON under an active Keep policy is a fail-closed denial")
		}
		if data.DenyReason == "" {
			t.Error("DenyReason should not be empty")
		}
		if data.ClientAddr == "" {
			t.Error("ClientAddr should not be empty")
		}
	})

	t.Run("policy deny (403)", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer backend.Close()

		eng := newEngine(t)
		p := &Proxy{
			credStore: &mockCredentialStore{tokens: map[string]string{}},
			mcpServers: []MCPServerConfig{
				{Name: "keep-test", URL: backend.URL, Auth: nil},
			},
		}

		var mu sync.Mutex
		var logged []RequestLogData
		p.SetLogger(func(data RequestLogData) {
			mu.Lock()
			defer mu.Unlock()
			logged = append(logged, data)
		})

		body := `{"method":"tools/call","params":{"name":"dangerous-tool","arguments":{}}}`
		req := httptest.NewRequest(http.MethodPost, "/mcp/keep-test", strings.NewReader(body))
		rc := &RunContextData{
			KeepEngines: map[string]*keeplib.Engine{"mcp-keep-test": eng},
			MCPServers:  p.mcpServers,
		}
		req = req.WithContext(context.WithValue(req.Context(), runContextKey, rc))

		rec := httptest.NewRecorder()
		p.handleMCPRelay(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
		}

		mu.Lock()
		defer mu.Unlock()
		if len(logged) != 1 {
			t.Fatalf("logged %d entries, want exactly 1: %+v", len(logged), logged)
		}
		data := logged[0]
		if data.StatusCode != http.StatusForbidden {
			t.Errorf("StatusCode = %d, want %d", data.StatusCode, http.StatusForbidden)
		}
		if !data.Denied {
			t.Error("Denied should be true — the Keep policy denied this tool call")
		}
		if data.DenyReason == "" {
			t.Error("DenyReason should not be empty")
		}
		if data.ClientAddr == "" {
			t.Error("ClientAddr should not be empty")
		}
	})

	// This subtest exercises the "missing params map" fail-closed branch of
	// the Redact case: encoding/json matches struct fields case-insensitively
	// when decoding into mcpReq, so a body whose top-level key is "PARAMS"
	// (rather than "params") still decodes into mcpReq.Params. But the
	// second decode — into a plain map[string]any — preserves the JSON key
	// exactly as written, so raw["params"] (lowercase) is absent even though
	// the policy layer above it already saw a populated Params.Name and
	// evaluated the call. This deterministically reaches the "missing
	// params map" branch without any fakes.
	t.Run("redaction fail-closed: missing params map (403)", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer backend.Close()

		eng, err := keeplib.LoadFromBytes([]byte(mcpRedactSecretRules))
		if err != nil {
			t.Fatalf("LoadFromBytes: %v", err)
		}
		defer eng.Close()

		p := &Proxy{
			credStore: &mockCredentialStore{tokens: map[string]string{}},
			mcpServers: []MCPServerConfig{
				{Name: "keep-test", URL: backend.URL, Auth: nil},
			},
		}

		var mu sync.Mutex
		var logged []RequestLogData
		p.SetLogger(func(data RequestLogData) {
			mu.Lock()
			defer mu.Unlock()
			logged = append(logged, data)
		})

		body := `{"method":"tools/call","PARAMS":{"name":"dangerous-tool","arguments":{"secret":"key is AKIAIOSFODNN7EXAMPLE"}}}`
		req := httptest.NewRequest(http.MethodPost, "/mcp/keep-test", strings.NewReader(body))
		rc := &RunContextData{
			KeepEngines: map[string]*keeplib.Engine{"mcp-keep-test": eng},
			MCPServers:  p.mcpServers,
		}
		req = req.WithContext(context.WithValue(req.Context(), runContextKey, rc))

		rec := httptest.NewRecorder()
		p.handleMCPRelay(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
		}

		mu.Lock()
		defer mu.Unlock()
		if len(logged) != 1 {
			t.Fatalf("logged %d entries, want exactly 1: %+v", len(logged), logged)
		}
		data := logged[0]
		if data.StatusCode != http.StatusForbidden {
			t.Errorf("StatusCode = %d, want %d", data.StatusCode, http.StatusForbidden)
		}
		if !data.Denied {
			t.Error("Denied should be true — the mutated MCP request lacked a params map, so it fails closed")
		}
		wantReason := "Keep policy redaction failed: body missing params map"
		if data.DenyReason != wantReason {
			t.Errorf("DenyReason = %q, want %q", data.DenyReason, wantReason)
		}
		if data.Err == nil {
			t.Error("Err should be set so this internal should-never-happen failure logs at ERROR, not WARN")
		}
	})
}
