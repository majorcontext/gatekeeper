package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// captureHandler records every log record as a flat map of its attributes.
type captureHandler struct {
	mu     sync.Mutex
	events []map[string]any
	block  chan struct{}
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *captureHandler) WithGroup(string) slog.Handler            { return h }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	if h.block != nil {
		<-h.block
	}
	m := map[string]any{"msg": r.Message}
	r.Attrs(func(a slog.Attr) bool {
		if a.Value.Kind() == slog.KindGroup {
			g := map[string]any{}
			for _, ga := range a.Value.Group() {
				g[ga.Key] = ga.Value.Any()
			}
			m[a.Key] = g
		} else {
			m[a.Key] = a.Value.Any()
		}
		return true
	})
	h.mu.Lock()
	h.events = append(h.events, m)
	h.mu.Unlock()
	return nil
}

// wait returns the event records once n of them exist.
func (h *captureHandler) wait(t *testing.T, n int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		if len(h.events) >= n {
			out := append([]map[string]any(nil), h.events...)
			h.mu.Unlock()
			return out
		}
		h.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d log events, have %d", n, len(h.events))
	return nil
}

func (h *captureHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.events)
}

func newExchangeProxy(t *testing.T, hosts ...string) (*Proxy, *captureHandler) {
	t.Helper()
	p := NewProxy()
	h := &captureHandler{}
	if err := p.SetExchangeLog(slog.New(h), hosts); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		p.CloseExchangeLog(ctx)
	})
	return p, h
}

const openAIIncomplete = "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"usage\":null}}\n\n" +
	"data: {\"type\":\"response.incomplete\",\"response\":{\"id\":\"resp_1\",\"status\":\"incomplete\"," +
	"\"incomplete_details\":{\"reason\":\"max_output_tokens\"},\"usage\":{\"input_tokens\":900000,\"output_tokens\":0}}}\n\n"

const anthropicStream = "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":10,\"cache_read_input_tokens\":500}}}\n\n" +
	"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":77}}\n\n" +
	"data: {\"type\":\"message_stop\"}\n\n"

// relayServer serves a relay to a backend on the proxy under test.
func relayServer(t *testing.T, p *Proxy, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	backend := httptest.NewServer(handler)
	t.Cleanup(backend.Close)
	if err := p.AddRelay("up", backend.URL); err != nil {
		t.Fatal(err)
	}
	host, _, _ := strings.Cut(strings.TrimPrefix(backend.URL, "http://"), ":")
	p.SetInsecureCredentialWithGrant(host, "Authorization", "Bearer sk-injected-secret-value", "g")
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	return srv
}

func post(t *testing.T, url, body string, hdr map[string]string) {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// The incident: a turn ended with max_output_tokens and 0 output tokens and the
// log must show the request, the ending, and no credential.
func TestExchangeLog_RecordsTheExchangeAndHidesCredentials(t *testing.T) {
	const tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	for _, tc := range []struct {
		name, path, stream, finish, id, usage string
		provider                              string
	}{
		{"openai incomplete", "/relay/up/responses", openAIIncomplete, "max_output_tokens", "resp_1", `"input_tokens":900000`, "openai"},
		{"anthropic", "/relay/up/v1/messages", anthropicStream, "end_turn", "msg_1", `"cache_read_input_tokens":500`, "anthropic"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, h := newExchangeProxy(t, "127.0.0.1")
			srv := relayServer(t, p, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprintf(w, ": echo %s\n\n", r.Header.Get("Authorization"))
				io.WriteString(w, tc.stream)
			})
			reqBody := `{"model":"m-1","tools":[{"name":"t1"}],"input":"hi"}`
			post(t, srv.URL+tc.path, reqBody, map[string]string{
				"Session_id": "ses_1", "Authorization": "Bearer placeholder", "Traceparent": tp,
			})
			ev := h.wait(t, 1)[0]
			requireBudgetReleased(t, p)
			for k, want := range map[string]any{
				"msg": ExchangeEventName, "gen_ai.operation.name": "chat", "gen_ai.provider.name": tc.provider,
				"gen_ai.request.model": "m-1", "gen_ai.response.id": tc.id, "gen_ai.conversation.id": "ses_1",
				"gatekeeper.request.body": reqBody, "http.response.status_code": int64(200),
			} {
				if ev[k] != want {
					t.Errorf("%s = %v, want %v", k, ev[k], want)
				}
			}
			if fr, _ := ev["gen_ai.response.finish_reasons"].([]string); len(fr) != 1 || fr[0] != tc.finish {
				t.Errorf("finish reasons = %v", ev["gen_ai.response.finish_reasons"])
			}
			if !strings.Contains(fmt.Sprint(ev["gatekeeper.usage"]), tc.usage) {
				t.Errorf("usage = %v", ev["gatekeeper.usage"])
			}
			if span, _ := ev["span"].(map[string]any); span["trace_id"] != "4bf92f3577b34da6a3ce929d0e0e4736" {
				t.Errorf("span = %v", ev["span"])
			}
			all, _ := json.Marshal(ev)
			for _, secret := range []string{"sk-injected-secret-value", "placeholder", tp} {
				if strings.Contains(string(all), secret) {
					t.Errorf("event contains %q: %s", secret, all)
				}
			}
			if !strings.Contains(fmt.Sprint(ev["gatekeeper.response.body"]), "[REDACTED]") {
				t.Errorf("echoed credential not redacted: %v", ev["gatekeeper.response.body"])
			}
		})
	}
}

func TestExchangeLog_LogsOnlyInferenceRequestsToListedHosts(t *testing.T) {
	for _, tc := range []struct {
		name, host, path string
		logged           bool
	}{
		{"listed", "127.0.0.1", "/relay/up/responses", true},
		{"other host", "api.example.org", "/relay/up/responses", false},
		{"not inference", "127.0.0.1", "/relay/up/models", false},
		{"not inference, messages of a thread", "127.0.0.1", "/relay/up/v1/threads/t/messages", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, h := newExchangeProxy(t, tc.host)
			srv := relayServer(t, p, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("{}")) })
			post(t, srv.URL+tc.path, `{}`, nil)
			post(t, srv.URL+"/relay/up/responses", `{}`, nil) // a second request proves the first one was not merely late
			time.Sleep(100 * time.Millisecond)
			want := 0
			if tc.logged {
				want = 2
			} else if tc.host == "127.0.0.1" {
				want = 1
			}
			if got := h.count(); got != want {
				t.Errorf("events = %d, want %d", got, want)
			}
		})
	}
}

func TestExchangeLog_StreamsUnbufferedAndNeverBlocksOnALogStall(t *testing.T) {
	p := NewProxy()
	h := &captureHandler{block: make(chan struct{})}
	if err := p.SetExchangeLog(slog.New(h), []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	defer close(h.block)
	release := make(chan struct{})
	srv := relayServer(t, p, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/responses" && r.Header.Get("X-Stream") != "" {
			io.WriteString(w, "data: {\"n\":1}\n\n")
			w.(http.Flusher).Flush()
			<-release
			io.WriteString(w, "data: {\"n\":2}\n\n")
			return
		}
		w.Write([]byte("ok"))
	})
	req, _ := http.NewRequest("POST", srv.URL+"/relay/up/responses", strings.NewReader("{}"))
	req.Header.Set("X-Stream", "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if n, err := resp.Body.Read(buf); err != nil || !strings.Contains(string(buf[:n]), `"n":1`) {
		t.Fatalf("first event was not forwarded before the upstream finished: %q %v", buf[:n], err)
	}
	close(release)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	for i := 0; i < 2*exchangeQueueLen; i++ { // the log goroutine is stuck; requests must not be
		post(t, srv.URL+"/relay/up/responses", "{}", nil)
	}
}

func TestExchangeLog_ChunksALargeBodyAndDecodesGzip(t *testing.T) {
	big := `{"model":"m","input":"` + strings.Repeat("é", 20_000) + `"}`
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(`{"id":"resp_gz","status":"completed","usage":{"output_tokens":7}}`))
	zw.Close()
	p, h := newExchangeProxy(t, "127.0.0.1")
	srv := relayServer(t, p, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(gz.Bytes())
	})
	post(t, srv.URL+"/relay/up/responses", big, nil)
	events := h.wait(t, 1+3)
	main, rebuilt := events[0], map[string]string{}
	if main["gatekeeper.request.body"] != nil || main["gatekeeper.request.parts"].(int64) != 3 {
		t.Fatalf("request was not chunked: parts=%v", main["gatekeeper.request.parts"])
	}
	for i, c := range events[1:] {
		if c["msg"] != ExchangeBodyEventName || c["gatekeeper.exchange.id"] != main["gatekeeper.exchange.id"] || c["gatekeeper.exchange.chunk_index"] != int64(i+1) {
			t.Fatalf("chunk %d = %v", i, c)
		}
		rebuilt["request"] += c["gatekeeper.exchange.data"].(string)
	}
	if rebuilt["request"] != big {
		t.Error("chunks do not rebuild the request")
	}
	if main["gen_ai.response.id"] != "resp_gz" || !strings.Contains(fmt.Sprint(main["gatekeeper.response.body"]), `"output_tokens":7`) {
		t.Errorf("gzip response was not decoded: %v", main)
	}
}

func TestExchangeLog_InterceptedTLS(t *testing.T) {
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, openAIIncomplete)
	}))
	setup.Proxy.SetCredentialWithGrant(setup.BackendHost, "x-api-key", "sk-ant-injected-0123456789", "g")
	h := &captureHandler{}
	if err := setup.Proxy.SetExchangeLog(slog.New(h), []string{setup.BackendHost}); err != nil {
		t.Fatal(err)
	}
	resp, err := setup.Client.Post(setup.Backend.URL+"/v1/messages", "application/json", strings.NewReader(`{"model":"claude-x"}`))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	ev := h.wait(t, 1)[0]
	if ev["gen_ai.request.model"] != "claude-x" || ev["gen_ai.provider.name"] != "anthropic" || ev["gen_ai.response.id"] != "resp_1" {
		t.Errorf("event = %v", ev)
	}
	if b, _ := json.Marshal(ev); strings.Contains(string(b), "sk-ant-injected") {
		t.Errorf("event holds the injected key: %s", b)
	}
}

func wsFrame(op byte, payload []byte, mask, fin bool) []byte {
	var b bytes.Buffer
	first := op
	if fin {
		first |= 0x80
	}
	b.WriteByte(first)
	m := byte(0)
	if mask {
		m = 0x80
	}
	if n := len(payload); n < 126 {
		b.WriteByte(m | byte(n))
	} else {
		b.WriteByte(m | 126)
		b.Write([]byte{byte(n >> 8), byte(n)})
	}
	if mask {
		b.Write([]byte{1, 2, 3, 4})
		for i, c := range payload {
			b.WriteByte(c ^ []byte{1, 2, 3, 4}[i&3])
		}
	} else {
		b.Write(payload)
	}
	return b.Bytes()
}

func readServerMessage(t *testing.T, r *bufio.Reader) {
	t.Helper()
	h := make([]byte, 2)
	io.ReadFull(r, h)
	n := int(h[1] & 0x7f)
	if n == 126 {
		e := make([]byte, 2)
		io.ReadFull(r, e)
		n = int(e[0])<<8 | int(e[1])
	}
	io.ReadFull(r, make([]byte, n))
}

// A Codex-style WebSocket carries many calls; each is one exchange with its own response ID.
func TestExchangeLog_WebSocketCallsAreExchanges(t *testing.T) {
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		conn, rw, _ := w.(http.Hijacker).Hijack()
		defer conn.Close()
		fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
		rw.Flush()
		for call := 1; ; call++ {
			h := make([]byte, 2)
			if _, err := io.ReadFull(rw, h); err != nil {
				return
			}
			n := int(h[1] & 0x7f)
			if n == 126 {
				e := make([]byte, 2)
				io.ReadFull(rw, e)
				n = int(e[0])<<8 | int(e[1])
			}
			io.ReadFull(rw, make([]byte, 4+n))
			if h[0]&0x80 == 0 || h[0]&0x0f == 9 { // answer only a complete message
				call--
				continue
			}
			rw.Write(wsFrame(1, []byte(fmt.Sprintf(`{"type":"response.created","response":{"id":"resp_%d"}}`, call)), false, true))
			rw.Write(wsFrame(1, []byte(`{"type":"response.incomplete","response":{"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"}}}`), false, true))
			rw.Flush()
		}
	}))
	setup.Proxy.SetCredentialWithGrant(setup.BackendHost, "Authorization", "Bearer sk-ws-injected-0123456789", "g")
	h := &captureHandler{}
	if err := setup.Proxy.SetExchangeLog(slog.New(h), []string{setup.BackendHost}); err != nil {
		t.Fatal(err)
	}

	proxyURL, _ := url.Parse(setup.ProxyServer.URL)
	raw, _ := net.Dial("tcp", proxyURL.Host)
	backend, _ := url.Parse(setup.Backend.URL)
	fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", backend.Host, backend.Host)
	if resp, err := http.ReadResponse(bufio.NewReader(raw), nil); err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(setup.CA.certPEM)
	conn := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: backend.Hostname(), NextProtos: []string{"http/1.1"}})
	defer conn.Close()
	fmt.Fprintf(conn, "GET /backend-api/codex/responses HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSession_id: ses_ws\r\n\r\n", backend.Host)
	cr := bufio.NewReader(conn)
	if resp, err := http.ReadResponse(cr, nil); err != nil || resp.StatusCode != 101 {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	for call := 1; call <= 2; call++ {
		req := []byte(fmt.Sprintf(`{"type":"response.create","model":"gpt-6","input":[{"role":"user","content":"call %d %s"}]}`, call, strings.Repeat("x", 300)))
		conn.Write(wsFrame(1, req[:20], true, false)) // a fragmented message, with a ping between the fragments
		conn.Write(wsFrame(9, []byte("hi"), true, true))
		conn.Write(wsFrame(0, req[20:], true, true))
		readServerMessage(t, cr)
		readServerMessage(t, cr)
	}
	events := h.wait(t, 2)
	conn.Close()
	requireBudgetReleased(t, setup.Proxy)
	for i, ev := range events[:2] {
		if ev["gen_ai.response.id"] != fmt.Sprintf("resp_%d", i+1) || ev["gen_ai.conversation.id"] != "ses_ws" || ev["gatekeeper.msg_seq"] != int64(i+1) ||
			ev["gatekeeper.transport"] != "websocket" || ev["gen_ai.request.model"] != "gpt-6" ||
			!strings.Contains(fmt.Sprint(ev["gatekeeper.request.body"]), fmt.Sprintf("call %d", i+1)) {
			t.Errorf("call %d = %v", i+1, ev)
		}
		if fr, _ := ev["gen_ai.response.finish_reasons"].([]string); len(fr) != 1 || fr[0] != "max_output_tokens" {
			t.Errorf("call %d finish = %v", i+1, ev["gen_ai.response.finish_reasons"])
		}
	}
}

// requireBudgetReleased fails when bodies stay counted after every exchange was written.
func requireBudgetReleased(t *testing.T, p *Proxy) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for p.exchangeLog.held.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if held := p.exchangeLog.held.Load(); held != 0 {
		t.Errorf("budget still holds %d bytes", held)
	}
}

func TestSetExchangeLog_Validation(t *testing.T) {
	lg := slog.New(&captureHandler{})
	for name, run := range map[string]func() error{
		"no logger": func() error { return NewProxy().SetExchangeLog(nil, []string{"a.com"}) },
		"no hosts":  func() error { return NewProxy().SetExchangeLog(lg, nil) },
		"bad host":  func() error { return NewProxy().SetExchangeLog(lg, []string{"a.com:x"}) },
		"twice": func() error {
			p := NewProxy()
			if err := p.SetExchangeLog(lg, []string{"a.com"}); err != nil {
				return nil
			}
			defer p.CloseExchangeLog(context.Background())
			return p.SetExchangeLog(lg, []string{"a.com"})
		},
	} {
		if run() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A 3-byte injected value cannot be scrubbed without mangling the body, so the
// response body is withheld instead.
func TestExchangeLog_WithholdsResponseWhenAnInjectedValueIsTooShortToScrub(t *testing.T) {
	p, h := newExchangeProxy(t, "127.0.0.1")
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"type\":\"message_stop\",\"id\":\"abc-1\"}\n\n")
	}))
	t.Cleanup(backend.Close)
	if err := p.AddRelay("up", backend.URL); err != nil {
		t.Fatal(err)
	}
	p.SetInsecureCredentialWithGrant("127.0.0.1", "Authorization", "Bearer abc", "g")
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	post(t, srv.URL+"/relay/up/v1/messages", `{"model":"m-1"}`, nil)
	ev := h.wait(t, 1)[0]
	if body := fmt.Sprint(ev["gatekeeper.response.body"]); strings.Contains(body, "abc") || strings.Contains(body, "message_stop") {
		t.Errorf("response body = %q, want it withheld", body)
	}
	if ev["gatekeeper.request.body"] != `{"model":"m-1"}` {
		t.Errorf("request body = %v", ev["gatekeeper.request.body"])
	}
}

func TestExchangeLog_PortPinnedHostPattern(t *testing.T) {
	for name, want := range map[string]int{"connect port": 1, "other port": 0} {
		t.Run(name, func(t *testing.T) {
			s := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, openAIIncomplete)
			}))
			_, port, _ := net.SplitHostPort(strings.TrimPrefix(s.Backend.URL, "https://"))
			if want == 0 {
				port = "1"
			}
			h := &captureHandler{}
			if err := s.Proxy.SetExchangeLog(slog.New(h), []string{s.BackendHost + ":" + port}); err != nil {
				t.Fatal(err)
			}
			resp, err := s.Client.Post(s.Backend.URL+"/v1/messages", "application/json", strings.NewReader(`{"model":"m"}`))
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			time.Sleep(100 * time.Millisecond)
			if got := h.count(); got != want {
				t.Errorf("events = %d, want %d", got, want)
			}
		})
	}
}

func TestExchangeLog_CutBodyWithoutInjectedValuesLogsWhole(t *testing.T) {
	p, h := newExchangeProxy(t, "127.0.0.1")
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "br")
		io.WriteString(w, openAIIncomplete)
	}))
	t.Cleanup(backend.Close)
	if err := p.AddRelay("up", backend.URL); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	post(t, srv.URL+"/relay/up/responses", `{"model":"m"}`, nil)
	h.wait(t, 1)
}

func TestExchangeLog_BodyClosedBeforeEOFDropsASecretPrefix(t *testing.T) {
	p, h := newExchangeProxy(t, "127.0.0.1")
	req := httptest.NewRequest("POST", "http://127.0.0.1/v1/messages", strings.NewReader(`{}`))
	ex := p.beginExchange(req, req, "127.0.0.1:80", "/v1/messages", time.Now())
	ex.secrets = []string{"sk-injected-secret-value"}
	resp := &http.Response{StatusCode: 400, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"error":"bad key sk-injected-secret-value"}`))}
	ex.wrapResponse(resp)
	resp.Body.Read(make([]byte, 30))
	resp.Body.Close()
	ev := h.wait(t, 1)[0]
	if b := fmt.Sprint(ev["gatekeeper.response.body"]); strings.Contains(b, "sk-injected") || ev["gatekeeper.response.truncated"] != true {
		t.Errorf("body = %q, truncated = %v", b, ev["gatekeeper.response.truncated"])
	}
}

func TestExchangeLog_RelayClientDisconnectDropsASecretPrefix(t *testing.T) {
	p, h := newExchangeProxy(t, "127.0.0.1")
	release := make(chan struct{})
	srv := relayServer(t, p, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"error":"bad key sk-injected-secret`)
		w.(http.Flusher).Flush()
		<-release
	})
	t.Cleanup(func() { close(release) })
	req := httptest.NewRequest("POST", srv.URL+"/relay/up/v1/messages", strings.NewReader(`{}`))
	req.URL.Scheme, req.URL.Host = "", ""
	ctx, cancel := context.WithCancel(req.Context())
	p.ServeHTTP(cancelOnWrite{httptest.NewRecorder(), cancel}, req.WithContext(ctx))
	ev := h.wait(t, 1)[0]
	if b := fmt.Sprint(ev["gatekeeper.response.body"]); strings.Contains(b, "sk-inject") || ev["gatekeeper.response.truncated"] != true {
		t.Errorf("body = %q, truncated = %v", b, ev["gatekeeper.response.truncated"])
	}
}

type cancelOnWrite struct {
	http.ResponseWriter
	cancel context.CancelFunc
}

func (c cancelOnWrite) Write(b []byte) (int, error) { c.cancel(); return 0, io.ErrClosedPipe }
