package proxy

import (
	"context"
	"net"
	"sync"
)

// connTracker tracks connections taken over with Hijack, which
// http.Server.Shutdown does not.
type connTracker struct {
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

// add registers c. It reports false once shutdown has begun. The returned
// func unregisters c and may be called more than once.
func (t *connTracker) add(c net.Conn) (done func(), ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, false
	}
	if t.conns == nil {
		t.conns = make(map[net.Conn]struct{})
	}
	t.conns[c] = struct{}{}
	t.wg.Add(1)
	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			delete(t.conns, c)
			t.mu.Unlock()
			t.wg.Done()
		})
	}, true
}

// trackedConn unregisters its connection on Close.
type trackedConn struct {
	net.Conn
	done func()
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.done()
	return err
}

// CloseConnections refuses new CONNECT tunnels and intercepted connections,
// closes the open ones, and waits for their goroutines to exit or ctx to end.
func (p *Proxy) CloseConnections(ctx context.Context) error {
	t := &p.conns
	t.mu.Lock()
	t.closed = true
	for c := range t.conns {
		_ = c.Close()
	}
	empty := len(t.conns) == 0
	t.mu.Unlock()
	if empty {
		return nil
	}

	drained := make(chan struct{})
	go func() {
		t.wg.Wait()
		close(drained)
	}()
	select {
	case <-drained:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
