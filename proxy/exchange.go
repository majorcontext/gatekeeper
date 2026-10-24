package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	exchangeCaptureLimit = 32 << 20  // largest body held in memory
	exchangeBudget       = 256 << 20 // all bodies in flight and queued
	exchangeQueueLen     = 256
	exchangeChunkBytes   = 16 << 10
	exchangeMinSecretLen = 8 // shorter values cannot be scrubbed without mangling the body
)

// ExchangeEventName is the OpenTelemetry GenAI event written for each exchange.
const ExchangeEventName = "gen_ai.client.inference.operation.details"

// ExchangeBodyEventName carries one chunk of a body larger than one chunk.
const ExchangeBodyEventName = "gatekeeper.exchange.body"

type exchangeLog struct {
	logger   *slog.Logger
	patterns []HostPattern
	queue    chan *exchange
	held     atomic.Int64
	done     chan struct{}
	mu       sync.RWMutex
	closed   bool
}

// SetExchangeLog logs the request and response of every inference request
// (OpenAI Responses and Anthropic Messages) to one of hosts, as a GenAI event
// on logger. Traffic to any other host is never captured. Call it once, before
// the proxy serves traffic.
func (p *Proxy) SetExchangeLog(logger *slog.Logger, hosts []string) error {
	if logger == nil || len(hosts) == 0 {
		return fmt.Errorf("exchange log: a logger and at least one host are required")
	}
	if p.exchangeLog != nil {
		return fmt.Errorf("exchange log: already set")
	}
	l := &exchangeLog{logger: logger, queue: make(chan *exchange, exchangeQueueLen), done: make(chan struct{})}
	for _, h := range hosts {
		pat, err := parseHostPatternChecked(h)
		if err != nil {
			return fmt.Errorf("exchange log: %w", err)
		}
		l.patterns = append(l.patterns, pat)
	}
	go l.run()
	p.exchangeLog = l
	return nil
}

// CloseExchangeLog stops accepting exchanges and waits for the queued ones to
// be written, until ctx ends.
func (p *Proxy) CloseExchangeLog(ctx context.Context) {
	l := p.exchangeLog
	if l == nil {
		return
	}
	l.mu.Lock()
	if !l.closed {
		l.closed = true
		close(l.queue)
	}
	l.mu.Unlock()
	select {
	case <-l.done:
	case <-ctx.Done():
	}
}

func (l *exchangeLog) run() {
	defer close(l.done)
	for ex := range l.queue {
		l.emit(ex)
		l.held.Add(-ex.reserved)
	}
}

func (l *exchangeLog) matches(host string) bool {
	port := 0
	if h, ps, err := net.SplitHostPort(host); err == nil {
		host = h
		port, _ = strconv.Atoi(ps)
	}
	for _, pat := range l.patterns {
		if pat.port != 0 && pat.port != port {
			continue
		}
		if pat.isWildcard && hostHasSuffixFold(host, "."+pat.host) || !pat.isWildcard && strings.EqualFold(pat.host, host) {
			return true
		}
	}
	return false
}

func (l *exchangeLog) reserve(n int) bool {
	if l.held.Add(int64(n)) > exchangeBudget {
		l.held.Add(-int64(n))
		return false
	}
	return true
}

// capBuf holds the first bytes of a body.
type capBuf struct {
	buf       bytes.Buffer
	total     int64
	truncated bool
}

// exchange is the state of one request until its response body closes.
type exchange struct {
	log                    *exchangeLog
	id, provider           string
	method, host, path     string
	user, session          string
	traceparent, tracestat string
	reqEnc, respEnc        string
	start                  time.Time

	mu       sync.Mutex
	req      capBuf
	resp     capBuf
	status   int
	ttfb     time.Duration
	total    time.Duration
	err      string
	secrets  []string
	reserved int64
	finished bool
	capped   bool // the budget refused a write; capture stopped
	upgrades bool // the exchange is on the interception path, which can follow a WebSocket

	connID string // WebSocket pairs only
	seq    int
}

// beginExchange returns the capture state for an inference request to a
// logged host, or nil. path is the path the upstream sees.
func (p *Proxy) beginExchange(r, req *http.Request, host, path string, start time.Time) *exchange {
	l := p.exchangeLog
	if l == nil {
		return nil
	}
	provider, ok := classifyExchange(path)
	if !ok || !l.matches(host) {
		return nil
	}
	if l.held.Load() >= exchangeBudget {
		RecordExchangeDrop(context.Background())
		return nil
	}
	id := req.Header.Get("X-Request-Id")
	if id == "" {
		id = RequestIDFromContext(r.Context())
	}
	if id == "" {
		id = newRequestID()
	}
	return &exchange{
		log: l, id: id, provider: provider, start: start,
		method: req.Method, host: bareHost(host), path: path,
		user:        userIDFromContext(r.Context()),
		session:     req.Header.Get("Session_id"),
		traceparent: req.Header.Get("Traceparent"), tracestat: req.Header.Get("Tracestate"),
		reqEnc: req.Header.Get("Content-Encoding"),
	}
}

// write appends p to b while the capture limit and the budget allow it.
// The caller holds ex.mu.
func (ex *exchange) write(b *capBuf, p []byte) {
	b.total += int64(len(p))
	if ex.finished || ex.capped || b.truncated {
		b.truncated = b.truncated || ex.capped
		return
	}
	n := min(len(p), exchangeCaptureLimit-b.buf.Len())
	if n < len(p) {
		b.truncated = true
	}
	if n > 0 {
		if !ex.log.reserve(n) {
			ex.capped, b.truncated = true, true
			return
		}
		ex.reserved += int64(n)
		b.buf.Write(p[:n])
	}
}

// wrapRequest tees the client's request body. It runs before any credential or
// token substitution, so the copy holds client bytes only.
func (ex *exchange) wrapRequest(req *http.Request) {
	if ex == nil || req.Body == nil || req.Body == http.NoBody {
		return
	}
	req.Body = &teeBody{rc: req.Body, ex: ex}
}

// noteOutbound records the injected credential values of out, so a response
// that echoes one can be redacted.
func (ex *exchange) noteOutbound(out *http.Request, res credentialInjectionResult, sub *TokenSubstitution) {
	if ex == nil {
		return
	}
	ex.mu.Lock()
	defer ex.mu.Unlock()
	add := func(v string) {
		if v = strings.TrimPrefix(strings.TrimSpace(v), "Bearer "); v != "" {
			ex.secrets = append(ex.secrets, v)
		}
	}
	for name := range res.InjectedHeaders {
		for _, v := range out.Header.Values(name) {
			add(v)
		}
	}
	for _, c := range res.Injected {
		add(c.Value) // before any header transform appended to it
	}
	if sub != nil {
		add(sub.realToken)
	}
}

// wrapResponse records the response headers and tees the body. The exchange
// finishes when the returned body closes.
func (ex *exchange) wrapResponse(resp *http.Response) {
	if ex == nil || resp.Body == nil {
		return
	}
	ex.mu.Lock()
	ex.status, ex.ttfb = resp.StatusCode, time.Since(ex.start)
	ex.respEnc = resp.Header.Get("Content-Encoding")
	ex.mu.Unlock()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		// The upgrade itself is not an exchange; a followed WebSocket logs its calls.
		ex.mu.Lock()
		ex.finished = true
		ex.log.held.Add(-ex.reserved)
		ex.reserved = 0
		ex.mu.Unlock()
		if ex.upgrades {
			ex.wrapUpgrade(resp)
		}
		return
	}
	resp.Body = &teeResponse{rc: resp.Body, ex: ex}
}

// fail finishes the exchange of a request that got no response.
func (ex *exchange) fail(err error, status int) {
	if ex == nil {
		return
	}
	ex.mu.Lock()
	ex.status = status
	if err != nil {
		ex.err = err.Error()
	}
	ex.mu.Unlock()
	ex.finish()
}

func (ex *exchange) finish() {
	if ex == nil {
		return
	}
	ex.mu.Lock()
	if ex.finished {
		ex.mu.Unlock()
		return
	}
	ex.finished = true
	ex.total = time.Since(ex.start)
	ex.mu.Unlock()
	l := ex.log
	l.mu.RLock()
	defer l.mu.RUnlock()
	if !l.closed {
		select {
		case l.queue <- ex:
			return
		default:
		}
	}
	ex.mu.Lock()
	l.held.Add(-ex.reserved)
	ex.mu.Unlock()
	RecordExchangeDrop(context.Background())
}

type teeBody struct {
	rc io.ReadCloser
	ex *exchange
}

func (t *teeBody) Read(p []byte) (int, error) {
	n, err := t.rc.Read(p)
	if n > 0 {
		t.ex.mu.Lock()
		t.ex.write(&t.ex.req, p[:n])
		t.ex.mu.Unlock()
	}
	return n, err
}

func (t *teeBody) Close() error { return t.rc.Close() }

type teeResponse struct {
	rc io.ReadCloser
	ex *exchange
}

func (t *teeResponse) Read(p []byte) (int, error) {
	n, err := t.rc.Read(p)
	if n > 0 || (err != nil && err != io.EOF) {
		t.ex.mu.Lock()
		t.ex.write(&t.ex.resp, p[:n])
		if err != nil && err != io.EOF && t.ex.err == "" {
			t.ex.err = "response body: " + err.Error()
		}
		t.ex.mu.Unlock()
	}
	return n, err
}

func (t *teeResponse) Close() error {
	err := t.rc.Close()
	t.ex.finish()
	return err
}

// emit writes the event of ex and one body event for each chunk of a body that
// does not fit one chunk. It runs on the log goroutine.
func (l *exchangeLog) emit(ex *exchange) {
	ex.mu.Lock()
	var (
		status, errText     = ex.status, ex.err
		ttfb, total         = ex.ttfb, ex.total
		secrets             = ex.secrets
		reqBytes, respBytes = ex.req.buf.Bytes(), ex.resp.buf.Bytes()
		reqTrunc, respTrunc = ex.req.truncated, ex.resp.truncated
		reqEnc, respEnc     = ex.reqEnc, ex.respEnc
	)
	ex.mu.Unlock() // the log handler may stall; a finishing request must not wait for it
	withhold := false
	scrub := func(s string) string {
		for _, sec := range secrets {
			if len(sec) < exchangeMinSecretLen {
				withhold = true
				continue
			}
			s = strings.ReplaceAll(s, sec, "[REDACTED]")
		}
		return s
	}
	reqText, reqCut := decodeBody(reqEnc, reqBytes)
	respText, respCut := decodeBody(respEnc, respBytes)
	respText = scrub(respText)
	if withhold {
		respText, respCut = "[WITHHELD: injected value too short to redact]", false
	}
	sum := summarize(respText)
	failed := status >= 400 || errText != ""
	if failed && sum.FinishReason == "" {
		sum.FinishReason = "error"
	}

	a := []slog.Attr{
		slog.String("event.name", ExchangeEventName),
		slog.String("gatekeeper.exchange.id", ex.id),
		slog.String("gen_ai.operation.name", "chat"),
		slog.String("gen_ai.provider.name", ex.provider),
		slog.String("http.request.method", ex.method),
		slog.String("server.address", ex.host),
		slog.String("url.path", scrub(ex.path)),
		slog.Int("http.response.status_code", status),
		slog.Float64("gatekeeper.ttfb_ms", float64(ttfb.Microseconds())/1e3),
		slog.Float64("gatekeeper.duration_ms", float64(total.Microseconds())/1e3),
	}
	str := func(k, v string) {
		if v != "" {
			a = append(a, slog.String(k, v))
		}
	}
	str("gen_ai.request.model", requestModel(reqText))
	str("gen_ai.response.id", sum.ResponseID)
	str("gen_ai.conversation.id", ex.session)
	str("gatekeeper.terminal.type", sum.Type)
	str("gatekeeper.usage", sum.Usage)
	str("gatekeeper.user_id", ex.user)
	str("gatekeeper.error", scrub(errText))
	if sum.FinishReason != "" {
		a = append(a, slog.Any("gen_ai.response.finish_reasons", []string{sum.FinishReason}))
	}
	if status >= 400 {
		a = append(a, slog.String("error.type", strconv.Itoa(status)))
	} else if errText != "" {
		a = append(a, slog.String("error.type", "stream_error"))
	}
	if ex.connID != "" {
		a = append(a, slog.String("gatekeeper.transport", "websocket"), slog.String("gatekeeper.conn_id", ex.connID), slog.Int("gatekeeper.msg_seq", ex.seq))
	}
	if reqTrunc || reqCut {
		a = append(a, slog.Bool("gatekeeper.request.truncated", true))
	}
	if respTrunc || respCut {
		a = append(a, slog.Bool("gatekeeper.response.truncated", true))
	}
	reqBody, reqChunks := chunkBody(reqText)
	respBody, respChunks := chunkBody(respText)
	a = append(a, slog.Int("gatekeeper.request.parts", max(len(reqChunks), 1)), slog.Int("gatekeeper.response.parts", max(len(respChunks), 1)))
	str("gatekeeper.request.body", reqBody)
	str("gatekeeper.response.body", respBody)

	ctx, sc := exchangeTraceContext(ex.traceparent, ex.tracestat)
	if sc.IsValid() {
		a = append(a, slog.Group("span", slog.String("trace_id", sc.TraceID().String()), slog.String("span_id", sc.SpanID().String())))
	}
	l.logger.LogAttrs(ctx, slog.LevelInfo, ExchangeEventName, a...)
	for _, body := range []struct {
		part   string
		chunks []string
	}{{"request", reqChunks}, {"response", respChunks}} {
		for i, c := range body.chunks {
			l.logger.LogAttrs(ctx, slog.LevelInfo, ExchangeBodyEventName,
				slog.String("event.name", ExchangeBodyEventName),
				slog.String("gatekeeper.exchange.id", ex.id),
				slog.String("gatekeeper.exchange.part", body.part),
				slog.Int("gatekeeper.exchange.chunk_index", i+1),
				slog.Int("gatekeeper.exchange.chunk_count", len(body.chunks)),
				slog.String("gatekeeper.exchange.data", c))
		}
	}
}

// chunkBody returns text when it fits one chunk, else its numbered chunks.
func chunkBody(text string) (string, []string) {
	text = strings.ToValidUTF8(text, "�")
	if len(text) <= exchangeChunkBytes {
		return text, nil
	}
	var chunks []string
	for len(text) > 0 {
		n := min(exchangeChunkBytes, len(text))
		for n < len(text) && n > 0 && text[n]&0xC0 == 0x80 {
			n--
		}
		chunks = append(chunks, text[:n])
		text = text[n:]
	}
	return "", chunks
}

// decodeBody returns b as text, decoded when it is gzip. cut reports a body
// that could not be fully decoded.
func decodeBody(encoding string, b []byte) (text string, cut bool) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return string(b), false
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return "[gatekeeper: gzip body not decoded]", true
		}
		out, err := io.ReadAll(io.LimitReader(zr, exchangeCaptureLimit+1))
		if len(out) > exchangeCaptureLimit {
			return string(out[:exchangeCaptureLimit]), true
		}
		return string(out), err != nil
	}
	return fmt.Sprintf("[gatekeeper: body encoded %q not logged]", encoding), true
}
