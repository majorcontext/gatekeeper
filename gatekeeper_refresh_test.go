package gatekeeper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

const refreshTestTTL = 4 * time.Minute

const refreshTestInterval = refreshTestTTL * 3 / 4

type scriptedRefreshSource struct {
	ttl   time.Duration
	fetch func(ctx context.Context, n int) (string, error)

	mu      sync.Mutex
	times   []time.Time
	stopped atomic.Bool
	late    atomic.Int32
}

func (s *scriptedRefreshSource) Fetch(ctx context.Context) (string, error) {
	if s.stopped.Load() {
		s.late.Add(1)
		runtime.Goexit()
	}
	s.mu.Lock()
	s.times = append(s.times, time.Now())
	n := len(s.times)
	s.mu.Unlock()
	if s.fetch != nil {
		return s.fetch(ctx, n)
	}
	return fmt.Sprintf("tok_%d", n), nil
}

func (s *scriptedRefreshSource) Type() string { return "scripted-refresh" }

func (s *scriptedRefreshSource) TTL() time.Duration { return s.ttl }

func (s *scriptedRefreshSource) fetchTimes() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time(nil), s.times...)
}

// refreshFixture serves credentials from one echo backend so a test can read
// back the headers the proxy injects. Both credentials target the loopback
// host with different headers: name resolution cannot run in a bubble, and a
// second IP literal host is not portable.
type refreshFixture struct {
	srv   *Server
	port  string
	creds []CredentialConfig
}

func startEchoBackend(t *testing.T) string {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, r.Header.Get("Authorization")+"|"+r.Header.Get("X-Api-Key"))
	}))
	t.Cleanup(backend.Close)
	u, _ := url.Parse(backend.URL)
	return u.Port()
}

func (f *refreshFixture) injected(t *testing.T) (authorization, apiKey string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:"+f.port+"/", nil)
	rec := httptest.NewRecorder()
	f.srv.proxy.ServeHTTP(rec, req)
	authorization, apiKey, _ = strings.Cut(rec.Body.String(), "|")
	return authorization, apiKey
}

func runRefreshBubble(t *testing.T, body func(t *testing.T, f *refreshFixture)) {
	t.Helper()
	port := startEchoBackend(t)
	synctest.Test(t, func(t *testing.T) {
		srv, err := New(context.Background(), &Config{
			Proxy:   ProxyConfig{Port: 0, Host: "127.0.0.1"},
			Network: NetworkConfig{Policy: "permissive"},
		}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		f := &refreshFixture{srv: srv, port: port, creds: []CredentialConfig{
			{Host: "127.0.0.1", Grant: "gh-a", AllowInsecure: true},
			{Host: "127.0.0.1", Grant: "gh-b", Header: "X-Api-Key", AllowInsecure: true},
		}}
		srv.proxy.SetInsecureCredentialWithGrant("127.0.0.1", "Authorization", "Bearer tok_0", "gh-a")
		srv.proxy.SetInsecureCredentialWithGrant("127.0.0.1", "X-Api-Key", "tok_0", "gh-b")
		body(t, f)
	})
}

func (f *refreshFixture) wantInjected(t *testing.T, when, token string) {
	t.Helper()
	authorization, apiKey := f.injected(t)
	if authorization != "Bearer "+token {
		t.Errorf("Authorization injected %s = %q, want %q", when, authorization, "Bearer "+token)
	}
	if apiKey != token {
		t.Errorf("X-Api-Key injected %s = %q, want %q", when, apiKey, token)
	}
}

func TestStartCredentialRefresh_RefetchesAt75PercentOfTTL(t *testing.T) {
	runRefreshBubble(t, func(t *testing.T, f *refreshFixture) {
		src := &scriptedRefreshSource{ttl: refreshTestTTL}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		start := time.Now()
		f.srv.startCredentialRefresh(ctx, src, f.creds)

		time.Sleep(refreshTestInterval - time.Second)
		synctest.Wait()
		if n := len(src.fetchTimes()); n != 0 {
			t.Fatalf("fetches at 1s before 75%% of a %v TTL = %d, want 0", refreshTestTTL, n)
		}

		time.Sleep(time.Second + refreshTestInterval)
		synctest.Wait()
		times := src.fetchTimes()
		if len(times) != 2 {
			t.Fatalf("fetches after two refresh intervals = %d, want 2", len(times))
		}
		if got := times[0].Sub(start); got != refreshTestInterval {
			t.Errorf("first refetch after %v, want %v (75%% of %v)", got, refreshTestInterval, refreshTestTTL)
		}
		if got := times[1].Sub(times[0]); got != refreshTestInterval {
			t.Errorf("second refetch %v after the first, want %v", got, refreshTestInterval)
		}
	})
}

func TestStartCredentialRefresh_HotSwapsEveryCredentialSharingTheSource(t *testing.T) {
	runRefreshBubble(t, func(t *testing.T, f *refreshFixture) {
		src := &scriptedRefreshSource{ttl: refreshTestTTL}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		f.srv.startCredentialRefresh(ctx, src, f.creds)

		time.Sleep(refreshTestInterval)
		synctest.Wait()
		f.wantInjected(t, "after the refresh", "tok_1")
	})
}

func TestStartCredentialRefresh_BacksOffThenResumesInterval(t *testing.T) {
	const failures = 9
	runRefreshBubble(t, func(t *testing.T, f *refreshFixture) {
		src := &scriptedRefreshSource{
			ttl: refreshTestTTL,
			fetch: func(_ context.Context, n int) (string, error) {
				if n <= failures {
					return "", errors.New("upstream down")
				}
				return "tok_ok", nil
			},
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		f.srv.startCredentialRefresh(ctx, src, f.creds)

		time.Sleep(40 * time.Minute)
		synctest.Wait()
		times := src.fetchTimes()
		if len(times) < failures+2 {
			t.Fatalf("fetches in 40m = %d, want at least %d", len(times), failures+2)
		}
		gap := func(i int) time.Duration { return times[i].Sub(times[i-1]) }

		if g := gap(1); g < time.Second || g >= time.Second*5/4 {
			t.Errorf("wait after the 1st failure = %v, want [1s, 1.25s)", g)
		}
		for i := 2; i < failures; i++ {
			floor := min(2*gap(i-1), time.Minute)
			if g := gap(i); g < floor || g >= floor*5/4 {
				t.Errorf("wait after failure %d = %v, want [%v, %v) (double the previous wait, capped at 1m)", i, g, floor, floor*5/4)
			}
		}
		if g := gap(failures + 1); g != refreshInterval(refreshTestTTL) {
			t.Errorf("wait after the first success = %v, want %v", g, refreshInterval(refreshTestTTL))
		}
	})
}

func TestStartCredentialRefresh_FailedRefreshKeepsLastCredential(t *testing.T) {
	runRefreshBubble(t, func(t *testing.T, f *refreshFixture) {
		src := &scriptedRefreshSource{
			ttl: refreshTestTTL,
			fetch: func(context.Context, int) (string, error) {
				return "", errors.New("upstream down")
			},
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		f.srv.startCredentialRefresh(ctx, src, f.creds)

		time.Sleep(10 * time.Minute)
		synctest.Wait()
		if n := len(src.fetchTimes()); n < 2 {
			t.Fatalf("fetches in 10m = %d, want at least 2", n)
		}
		f.wantInjected(t, "after failed refreshes", "tok_0")
	})
}

func TestStartCredentialRefresh_CancelEndsTheLoop(t *testing.T) {
	blockUntilCancel := func(ctx context.Context, _ int) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}
	alwaysFail := func(context.Context, int) (string, error) { return "", errors.New("upstream down") }
	tests := []struct {
		name     string
		fetch    func(ctx context.Context, n int) (string, error)
		cancelAt time.Duration
		inFlight bool
	}{
		{"waiting for the first refresh", nil, time.Minute, false},
		{"waiting out a backoff", alwaysFail, refreshTestInterval + 500*time.Millisecond, false},
		{"fetch in flight", blockUntilCancel, refreshTestInterval + time.Second, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runRefreshBubble(t, func(t *testing.T, f *refreshFixture) {
				var fetchEnd atomic.Pointer[error]
				fetch := tt.fetch
				if tt.inFlight {
					fetch = func(ctx context.Context, n int) (string, error) {
						v, err := tt.fetch(ctx, n)
						fetchEnd.Store(&err)
						return v, err
					}
				}
				src := &scriptedRefreshSource{ttl: refreshTestTTL, fetch: fetch}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				f.srv.startCredentialRefresh(ctx, src, f.creds)

				time.Sleep(tt.cancelAt)
				synctest.Wait()
				src.stopped.Store(true)
				cancel()
				synctest.Wait()
				if tt.inFlight {
					if err := fetchEnd.Load(); err == nil || !errors.Is(*err, context.Canceled) {
						t.Errorf("in-flight fetch ended with %v, want context.Canceled", err)
					}
				}
				time.Sleep(time.Hour)
				synctest.Wait()
				if n := src.late.Load(); n != 0 {
					t.Errorf("fetches after cancel = %d, want 0", n)
				}
			})
		})
	}
}
