package gatekeeper

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/majorcontext/gatekeeper/credentialsource"
)

type countingSource struct{ fetches *atomic.Int32 }

func (c countingSource) Fetch(context.Context) (string, error) {
	c.fetches.Add(1)
	return "shared-secret", nil
}
func (c countingSource) Type() string { return "counting" }

func newBareServer(t *testing.T) *Server {
	t.Helper()
	srv, err := New(context.Background(), &Config{Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func TestLoadCredentials_PostgresStaticSharesSourceWithHeaderCredential(t *testing.T) {
	srv := newBareServer(t)
	var fetches atomic.Int32
	srv.resolveSource = func(SourceConfig) (credentialsource.CredentialSource, error) {
		return countingSource{&fetches}, nil
	}
	src := SourceConfig{Type: "env", Var: "SHARED"}
	cfg := &Config{Credentials: []CredentialConfig{
		{Host: "api.example.com", Grant: "api", Source: src},
		{Host: "db1.example.com", Grant: "db1", Source: src, Postgres: &PostgresCredentialConfig{Resolver: "static"}},
		{Host: "db2.example.com", Grant: "db2", Source: src, Postgres: &PostgresCredentialConfig{Resolver: "static"}},
	}}
	if err := srv.loadCredentials(context.Background(), cfg); err != nil {
		t.Fatalf("loadCredentials: %v", err)
	}
	if got := fetches.Load(); got != 1 {
		t.Errorf("Fetch calls for one source shared by a header credential and two postgres credentials = %d, want 1", got)
	}
}

func TestLoadCredentials_PostgresStaticFetchesConcurrentlyWithHeaderSources(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		srv := newBareServer(t)
		arrived := make(chan struct{}, 2)
		gate := make(chan struct{})
		srv.resolveSource = func(sc SourceConfig) (credentialsource.CredentialSource, error) {
			return gateSource{arrived: arrived, gate: gate, name: sc.Secret}, nil
		}
		cfg := &Config{Credentials: []CredentialConfig{
			{Host: "db.example.com", Grant: "db", Source: SourceConfig{Type: "mock", Secret: "db"}, Postgres: &PostgresCredentialConfig{Resolver: "static"}},
			{Host: "api.example.com", Grant: "api", Source: SourceConfig{Type: "mock", Secret: "api"}},
		}}
		done := make(chan error, 1)
		go func() { done <- srv.loadCredentials(context.Background(), cfg) }()
		for i := 0; i < 2; i++ {
			select {
			case <-arrived:
			case err := <-done:
				t.Fatalf("loadCredentials returned with %d of 2 fetches in flight: %v", i, err)
			}
		}
		close(gate)
		if err := <-done; err != nil {
			t.Fatalf("loadCredentials: %v", err)
		}
	})
}

func TestLoadCredentials_IdenticalTokenExchangeBlocksShareOneCache(t *testing.T) {
	var exchanges atomic.Int32
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "exchanged", "expires_in": 3600})
	}))
	defer sts.Close()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	port := mustURL(t, backend.URL).Port()

	srv := newBareServer(t)
	te := SourceConfig{Type: "token-exchange", Endpoint: sts.URL, ClientID: "c", ClientSecret: "s", SubjectHeader: "X-Subject"}
	cfg := &Config{Credentials: []CredentialConfig{
		{Host: "127.0.0.1", Grant: "a", Source: te, AllowInsecure: true},
		{Host: "localhost", Grant: "b", Source: te, AllowInsecure: true},
	}}
	if err := srv.loadCredentials(context.Background(), cfg); err != nil {
		t.Fatalf("loadCredentials: %v", err)
	}
	for _, host := range []string{"127.0.0.1", "localhost"} {
		req := httptest.NewRequest(http.MethodGet, "http://"+host+":"+port+"/", nil)
		req.Header.Set("X-Subject", "alice")
		rec := httptest.NewRecorder()
		srv.proxy.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET via %s = %d, want 200", host, rec.Code)
		}
	}
	if got := exchanges.Load(); got != 1 {
		t.Errorf("STS exchanges for one subject across two hosts with identical token-exchange blocks = %d, want 1", got)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

type blockUntilCanceledSource struct{ saw chan<- error }

func (b blockUntilCanceledSource) Fetch(ctx context.Context) (string, error) {
	<-ctx.Done()
	b.saw <- ctx.Err()
	return "", errors.New("signal: killed")
}
func (b blockUntilCanceledSource) Type() string { return "block" }

type failNowSource struct{ ready <-chan struct{} }

func (f failNowSource) Fetch(context.Context) (string, error) {
	<-f.ready
	return "", errors.New("boom b")
}
func (f failNowSource) Type() string { return "fail" }

func TestLoadCredentials_FirstFetchFailureCancelsTheOtherFetches(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		srv := newBareServer(t)
		saw := make(chan error, 1)
		ready := make(chan struct{})
		srv.resolveSource = func(sc SourceConfig) (credentialsource.CredentialSource, error) {
			if sc.Secret == "a" {
				return blockUntilCanceledSource{saw: saw}, nil
			}
			return failNowSource{ready: ready}, nil
		}
		cfg := &Config{Credentials: []CredentialConfig{
			{Host: "a.example.com", Grant: "a", Source: SourceConfig{Type: "mock", Secret: "a"}},
			{Host: "b.example.com", Grant: "b", Source: SourceConfig{Type: "mock", Secret: "b"}},
		}}
		done := make(chan error, 1)
		go func() { done <- srv.loadCredentials(context.Background(), cfg) }()
		synctest.Wait()
		close(ready)
		err := <-done
		if err == nil || !strings.Contains(err.Error(), "b.example.com") || !strings.Contains(err.Error(), "boom b") {
			t.Fatalf("err = %v, want the failure of b.example.com", err)
		}
		if got := <-saw; !errors.Is(got, context.Canceled) {
			t.Errorf("blocked fetch ended with %v, want context.Canceled (not the 10s timeout)", got)
		}
	})
}
