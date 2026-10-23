package gatekeeper

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestModelExchangeConfigLogsOnlyListedHosts(t *testing.T) {
	cfg, err := ParseConfig([]byte("log:\n  model_exchange:\n    enabled: true\n    hosts: [\"127.0.0.1\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	var buf syncLogBuffer
	server, err := New(context.Background(), cfg, Options{Logger: slog.New(slog.NewJSONHandler(&buf, nil))})
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Write([]byte(`{"id":"resp_1","status":"completed"}`))
	}))
	defer backend.Close()
	proxyServer := httptest.NewServer(server.proxy)
	defer proxyServer.Close()
	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Post(backend.URL+"/v1/responses", "application/json", strings.NewReader(`{"model":"m1"}`))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if err := server.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{`"msg":"gen_ai.client.inference.operation.details"`, `"gen_ai.request.model":"m1"`, `"gen_ai.response.id":"resp_1"`} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %s:\n%s", want, out)
		}
	}
}

func TestModelExchangeRequiresHosts(t *testing.T) {
	cfg := &Config{Log: LogConfig{ModelExchange: ModelExchangeConfig{Enabled: true}}}
	if _, err := New(context.Background(), cfg, Options{}); err == nil {
		t.Fatal("New accepted model_exchange without hosts")
	}
}
