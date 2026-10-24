package proxy

import (
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A WebSocket upgrade carries many calls on one connection: the client sends a
// text message that holds the request, and the server answers with event
// messages up to a terminal event. The tap parses both directions as the bytes
// pass and logs each call as one exchange.
type wsTap struct {
	base    *exchange
	mu      sync.Mutex
	client  wsParser
	server  wsParser
	pending *exchange
	seq     int
	closed  bool
}

type teeConn struct {
	rwc io.ReadWriteCloser
	tap *wsTap
}

func (c *teeConn) Read(p []byte) (int, error) {
	n, err := c.rwc.Read(p)
	if n > 0 {
		c.tap.feed(false, p[:n])
	}
	return n, err
}

// Write feeds the tap first: the server cannot answer bytes it has not
// received, so the tap never sees a reply before its request.
func (c *teeConn) Write(p []byte) (int, error) {
	c.tap.feed(true, p)
	return c.rwc.Write(p)
}

// CloseWrite half-closes the upstream side when it can, as the reverse proxy
// expects of a connection that supports it.
func (c *teeConn) CloseWrite() error {
	if cw, ok := c.rwc.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return http.ErrNotSupported
}

func (c *teeConn) Close() error {
	err := c.rwc.Close()
	c.tap.end("connection closed before a terminal event")
	return err
}

// wrapUpgrade follows a WebSocket upgrade. It reports false for any other
// upgrade, and for one that negotiated an extension such as compression.
func (ex *exchange) wrapUpgrade(resp *http.Response) bool {
	rwc, ok := resp.Body.(io.ReadWriteCloser)
	if !ok || !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") || resp.Header.Get("Sec-WebSocket-Extensions") != "" {
		return false
	}
	t := &wsTap{base: ex}
	t.client = wsParser{log: ex.log}
	t.server = wsParser{log: ex.log}
	resp.Body = &teeConn{rwc: rwc, tap: t}
	return true
}

func (t *wsTap) feed(fromClient bool, b []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	p := &t.server
	if fromClient {
		p = &t.client
	}
	p.feed(b, func(msg []byte, truncated bool) {
		if fromClient {
			t.endLocked("superseded by a new request")
			t.seq++
			t.pending = t.base.newCall(t.seq, msg, truncated)
			return
		}
		if t.pending == nil {
			return
		}
		ex := t.pending
		ex.mu.Lock()
		if ex.ttfb == 0 {
			ex.ttfb = time.Since(ex.start)
		}
		ex.write(&ex.resp, msg)
		ex.write(&ex.resp, []byte("\n"))
		ex.mu.Unlock()
		if isTerminalMessage(msg) {
			t.endLocked("")
		}
	})
}

func (t *wsTap) end(reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	t.endLocked(reason)
	t.client.reset()
	t.server.reset()
}

func (t *wsTap) endLocked(reason string) {
	if t.pending == nil {
		return
	}
	t.pending.mu.Lock()
	t.pending.err = reason
	t.pending.mu.Unlock()
	t.pending.finish()
	t.pending = nil
}

// newCall returns the exchange of one client message.
func (ex *exchange) newCall(seq int, body []byte, truncated bool) *exchange {
	m := &exchange{
		log: ex.log, id: ex.id + "." + strconv.Itoa(seq), connID: ex.id, seq: seq,
		start: time.Now(), method: ex.method, host: ex.host, path: ex.path, provider: ex.provider,
		user: ex.user, session: ex.session, traceparent: ex.traceparent, tracestat: ex.tracestat,
		status: http.StatusSwitchingProtocols, secrets: ex.secrets,
	}
	m.mu.Lock()
	m.write(&m.req, body)
	m.req.truncated = m.req.truncated || truncated
	m.mu.Unlock()
	return m
}

var terminalType = regexp.MustCompile(`"type"\s*:\s*"(response\.(completed|incomplete|failed)|error)"`)

// isTerminalMessage reports a terminal event by the type in the head of the
// message, whatever the spacing of the JSON.
func isTerminalMessage(msg []byte) bool {
	return terminalType.Match(msg[:min(len(msg), 200)])
}

// wsParser reassembles the text messages of one direction of a WebSocket
// stream. Control frames and binary messages are skipped.
type wsParser struct {
	log *exchangeLog

	hdr       []byte
	remaining int64
	key       [4]byte
	frameMask bool
	keyPos    int
	fin       bool
	op        byte
	inMessage bool
	msg       []byte
	held      int
	truncated bool
	bad       bool
}

func (p *wsParser) feed(b []byte, emit func(msg []byte, truncated bool)) {
	for len(b) > 0 && !p.bad {
		if p.remaining > 0 {
			n := int(min(int64(len(b)), p.remaining))
			p.payload(b[:n])
			b = b[n:]
			if p.remaining -= int64(n); p.remaining == 0 {
				p.endFrame(emit)
			}
			continue
		}
		p.hdr = append(p.hdr, b[0])
		b = b[1:]
		if p.parseHeader() && p.remaining == 0 {
			p.endFrame(emit)
		}
	}
}

func (p *wsParser) parseHeader() bool {
	h := p.hdr
	if len(h) < 2 {
		return false
	}
	n, need := int64(h[1]&0x7f), 2
	switch n {
	case 126:
		need += 2
	case 127:
		need += 8
	}
	p.frameMask = h[1]&0x80 != 0
	if p.frameMask {
		need += 4
	}
	if len(h) < need {
		return false
	}
	switch n {
	case 126:
		n = int64(h[2])<<8 | int64(h[3])
	case 127:
		n = 0
		for _, c := range h[2:10] {
			n = n<<8 | int64(c)
		}
	}
	if n < 0 {
		p.bad = true
		return true
	}
	p.fin, p.op = h[0]&0x80 != 0, h[0]&0x0f
	if p.frameMask {
		copy(p.key[:], h[need-4:need])
	}
	p.keyPos, p.remaining, p.hdr = 0, n, p.hdr[:0]
	if p.op == 1 || p.op == 2 {
		p.reset()
		p.inMessage = p.op == 1
	}
	return true
}

func (p *wsParser) payload(b []byte) {
	if p.op >= 8 || !p.inMessage || p.truncated {
		p.keyPos += len(b)
		return
	}
	n := min(len(b), exchangeCaptureLimit-len(p.msg))
	if n < len(b) || !p.log.reserve(n) {
		p.truncated = true
		n = 0
	} else {
		p.held += n
	}
	start := len(p.msg)
	p.msg = append(p.msg, b[:n]...)
	if p.frameMask {
		for i := start; i < len(p.msg); i++ {
			p.msg[i] ^= p.key[p.keyPos&3]
			p.keyPos++
		}
	} else {
		p.keyPos += n
	}
	p.keyPos += len(b) - n
}

func (p *wsParser) endFrame(emit func(msg []byte, truncated bool)) {
	if p.op >= 8 || !p.fin || !p.inMessage {
		return
	}
	emit(p.msg, p.truncated)
	p.reset()
}

// reset drops the message under assembly and returns its budget.
func (p *wsParser) reset() {
	p.log.held.Add(-int64(p.held))
	p.held, p.msg, p.truncated, p.inMessage = 0, nil, false, false
}
