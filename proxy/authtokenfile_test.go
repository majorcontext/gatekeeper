package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"
)

// writeK8sToken lays out dir like a Kubernetes Secret volume:
// token -> ..data/token, ..data -> ..<gen>.
func writeK8sToken(t *testing.T, dir, gen, value string) {
	t.Helper()
	genDir := filepath.Join(dir, ".."+gen)
	if err := os.MkdirAll(genDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(genDir, "token"), []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, "..data_tmp")
	_ = os.Remove(tmp)
	if err := os.Symlink(".."+gen, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "token")
	if _, err := os.Lstat(link); err != nil {
		if err := os.Symlink(filepath.Join("..data", "token"), link); err != nil {
			t.Fatal(err)
		}
	}
}

func proxyStatusWithToken(t *testing.T, p *Proxy, backendURL, token string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, backendURL, nil)
	req.SetBasicAuth("box", token)
	req.Header.Set("Proxy-Authorization", req.Header.Get("Authorization"))
	req.Header.Del("Authorization")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	return rec.Code
}

func TestReloadAuthTokenFile_SwapsTokenForHTTPAndPostgres(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	writeK8sToken(t, dir, "gen1", "old-token\n")

	p := NewProxy()
	p.SetAuthToken("old-token")
	pg := NewPostgresServer(p)

	if got := proxyStatusWithToken(t, p, backend.URL, "old-token"); got == http.StatusProxyAuthRequired {
		t.Fatalf("old token before swap: status %d, want accepted", got)
	}
	if _, ok := pg.authenticate("old-token"); !ok {
		t.Fatal("postgres: old token before swap rejected")
	}

	writeK8sToken(t, dir, "gen2", "new-token\n")
	changed, err := p.ReloadAuthTokenFile(path)
	if err != nil || !changed {
		t.Fatalf("ReloadAuthTokenFile = %v, %v; want true, nil", changed, err)
	}

	if got := proxyStatusWithToken(t, p, backend.URL, "new-token"); got == http.StatusProxyAuthRequired {
		t.Errorf("http: new token status %d, want accepted", got)
	}
	if got := proxyStatusWithToken(t, p, backend.URL, "old-token"); got != http.StatusProxyAuthRequired {
		t.Errorf("http: old token status %d, want 407", got)
	}
	if _, ok := pg.authenticate("new-token"); !ok {
		t.Error("postgres: new token rejected")
	}
	if _, ok := pg.authenticate("old-token"); ok {
		t.Error("postgres: old token accepted after reload")
	}
}

func TestReloadAuthTokenFile_EmptyOrMissingKeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	writeK8sToken(t, dir, "gen1", "old-token")
	p := NewProxy()
	p.SetAuthToken("old-token")
	pg := NewPostgresServer(p)

	writeK8sToken(t, dir, "gen2", " \n")
	if changed, err := p.ReloadAuthTokenFile(path); err == nil || changed {
		t.Errorf("empty file: changed=%v err=%v; want false, error", changed, err)
	}
	if _, err := p.ReloadAuthTokenFile(filepath.Join(dir, "absent")); err == nil {
		t.Error("missing file: want error")
	}
	if _, ok := pg.authenticate("old-token"); !ok {
		t.Error("previous token dropped after a bad reload")
	}
	if _, ok := pg.authenticate(""); ok {
		t.Error("empty token accepted after empty-file reload")
	}
}

func TestWatchAuthTokenFile_PicksUpSwap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "token")
		writeK8sToken(t, dir, "gen1", "old-token")
		p := NewProxy()
		p.SetAuthToken("old-token")
		pg := NewPostgresServer(p)

		ctx, cancel := context.WithCancel(context.Background())
		go p.WatchAuthTokenFile(ctx, path, time.Second)
		synctest.Wait()

		writeK8sToken(t, dir, "gen2", "new-token")
		time.Sleep(2 * time.Second)
		synctest.Wait()

		if _, ok := pg.authenticate("new-token"); !ok {
			t.Error("new token not picked up by watcher")
		}
		if _, ok := pg.authenticate("old-token"); ok {
			t.Error("old token still accepted after watcher tick")
		}
		cancel()
		synctest.Wait()
	})
}
