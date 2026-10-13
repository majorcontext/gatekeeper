package gatekeeper

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/majorcontext/gatekeeper/credentialsource"
)

type blockingSource struct {
	calls     atomic.Int32
	entered   chan struct{}
	canceled  chan struct{}
	release   chan struct{}
	result    error
	inFlight  atomic.Int32
	returned  atomic.Bool
	closedMid atomic.Bool
	closed    atomic.Bool
}

func (b *blockingSource) Fetch(ctx context.Context) (string, error) {
	if b.calls.Add(1) == 1 {
		return "tok", nil
	}
	b.inFlight.Add(1)
	b.entered <- struct{}{}
	<-ctx.Done()
	close(b.canceled)
	<-b.release
	b.returned.Store(true)
	b.inFlight.Add(-1)
	return "tok", b.result
}

func (b *blockingSource) Type() string       { return "blocking" }
func (b *blockingSource) TTL() time.Duration { return 0 }

func (b *blockingSource) Close() error {
	b.closed.Store(true)
	if b.inFlight.Load() > 0 {
		b.closedMid.Store(true)
	}
	return nil
}

type recordingHandler struct {
	mu   sync.Mutex
	msgs []string
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.msgs = append(h.msgs, r.Message)
	return nil
}
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingHandler) refreshMessages() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, m := range h.msgs {
		if strings.HasPrefix(m, "credential refresh") {
			out = append(out, m)
		}
	}
	return out
}

func startBlockedRefresh(t *testing.T, result error) (*Server, *blockingSource, *recordingHandler) {
	t.Helper()
	prevFloor := refreshFloor
	refreshFloor = time.Millisecond
	t.Cleanup(func() { refreshFloor = prevFloor })

	logs := &recordingHandler{}
	prevLog := slog.Default()
	slog.SetDefault(slog.New(logs))
	t.Cleanup(func() { slog.SetDefault(prevLog) })

	src := &blockingSource{
		entered:  make(chan struct{}, 1),
		canceled: make(chan struct{}),
		release:  make(chan struct{}),
		result:   result,
	}
	srv, err := New(context.Background(), &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	srv.resolveSource = func(SourceConfig) (credentialsource.CredentialSource, error) {
		return src, nil
	}
	if err := srv.loadCredentials(context.Background(), &Config{
		Credentials: []CredentialConfig{{Host: "api.github.com", Source: SourceConfig{Type: "mock"}, Grant: "gh"}},
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	startDone := make(chan struct{})
	go func() { defer close(startDone); _ = srv.Start(ctx) }()
	t.Cleanup(func() { cancel(); <-startDone })

	<-src.entered
	return srv, src, logs
}

func TestStop_WaitsForInFlightRefresh(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result error
	}{
		{"fetch fails after stop", errors.New("context canceled by shutdown")},
		{"fetch succeeds after stop", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, src, logs := startBlockedRefresh(t, tc.result)

			stopDone := make(chan struct{})
			stopReturnedAfterFetch := make(chan bool, 1)
			go func() {
				_ = srv.Stop(context.Background())
				stopReturnedAfterFetch <- src.returned.Load()
				close(stopDone)
			}()
			<-src.canceled
			close(src.release)
			<-stopDone

			if !<-stopReturnedAfterFetch {
				t.Error("Stop returned while a refresh Fetch was still in flight")
			}
			if src.closedMid.Load() {
				t.Error("source closed while a refresh Fetch was in flight")
			}
			if got := logs.refreshMessages(); len(got) != 0 {
				t.Errorf("refresh activity logged after Stop: %q", got)
			}
		})
	}
}

func TestStop_DeadlineBoundsRefreshWait(t *testing.T) {
	srv, src, _ := startBlockedRefresh(t, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = srv.Stop(ctx)

	if src.closed.Load() {
		t.Error("source closed although a refresh Fetch was still in flight at the Stop deadline")
	}
	close(src.release)
}
