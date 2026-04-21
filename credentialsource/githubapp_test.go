package credentialsource

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func generateTestKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return key, keyPEM
}

func TestGitHubAppSource_JWT(t *testing.T) {
	key, keyPEM := generateTestKey(t)

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		expiresAt := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"token":      "ghs_test123",
			"expires_at": expiresAt,
		})
	}))
	defer srv.Close()

	src, err := NewGitHubAppSource("12345", "67890", keyPEM)
	if err != nil {
		t.Fatalf("NewGitHubAppSource: %v", err)
	}
	src.apiBaseURL = srv.URL

	_, err = src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if len(gotAuth) < 8 || gotAuth[:7] != "Bearer " {
		t.Fatalf("Authorization = %q, want Bearer prefix", gotAuth)
	}
	jwt := gotAuth[7:]

	parts := splitJWT(t, jwt)

	headerJSON := decodeBase64URL(t, parts[0])
	var header map[string]string
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("decoding JWT header: %v", err)
	}
	if header["alg"] != "RS256" {
		t.Errorf("JWT alg = %q, want RS256", header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Errorf("JWT typ = %q, want JWT", header["typ"])
	}

	claimsJSON := decodeBase64URL(t, parts[1])
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("decoding JWT claims: %v", err)
	}
	if claims["iss"] != "12345" {
		t.Errorf("JWT iss = %v, want 12345", claims["iss"])
	}
	iat := int64(claims["iat"].(float64))
	exp := int64(claims["exp"].(float64))
	now := time.Now().Unix()
	if iat > now || iat < now-120 {
		t.Errorf("JWT iat = %d, want ~%d (backdated 60s)", iat, now-60)
	}
	if exp-iat < 500 || exp-iat > 700 {
		t.Errorf("JWT exp-iat = %d, want ~600", exp-iat)
	}

	verifyRS256(t, parts[0]+"."+parts[1], parts[2], &key.PublicKey)
}

func splitJWT(t *testing.T, jwt string) [3]string {
	t.Helper()
	var parts [3]string
	a, b := 0, 0
	idx := 0
	for i, c := range jwt {
		if c == '.' {
			parts[idx] = jwt[a:i]
			idx++
			a = i + 1
		}
		b = i
	}
	if idx != 2 {
		t.Fatalf("JWT has %d dots, want 2", idx)
	}
	parts[2] = jwt[a : b+1]
	return parts
}

func decodeBase64URL(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url decode: %v", err)
	}
	return b
}

func verifyRS256(t *testing.T, message, sig string, pub *rsa.PublicKey) {
	t.Helper()
	sigBytes := decodeBase64URL(t, sig)
	hash := sha256.Sum256([]byte(message))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sigBytes); err != nil {
		t.Fatalf("RS256 signature verification failed: %v", err)
	}
}

func TestGitHubAppSource_FetchAndTTL(t *testing.T) {
	_, keyPEM := generateTestKey(t)

	expiresAt := time.Now().Add(1 * time.Hour).UTC()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		wantPath := "/app/installations/67890/access_tokens"
		if r.URL.Path != wantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, wantPath)
		}
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("Accept = %s, want application/vnd.github+json", r.Header.Get("Accept"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"token":      "ghs_testtoken",
			"expires_at": expiresAt.Format(time.RFC3339),
		})
	}))
	defer srv.Close()

	src, err := NewGitHubAppSource("12345", "67890", keyPEM)
	if err != nil {
		t.Fatalf("NewGitHubAppSource: %v", err)
	}
	src.apiBaseURL = srv.URL

	if ttl := src.TTL(); ttl != 0 {
		t.Errorf("TTL before Fetch = %v, want 0", ttl)
	}

	token, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if token != "ghs_testtoken" {
		t.Errorf("token = %q, want %q", token, "ghs_testtoken")
	}
	if src.Type() != "github-app" {
		t.Errorf("Type() = %q, want %q", src.Type(), "github-app")
	}

	ttl := src.TTL()
	if ttl < 59*time.Minute || ttl > 61*time.Minute {
		t.Errorf("TTL = %v, want ~1h", ttl)
	}
}

func TestGitHubAppSource_InvalidPEM(t *testing.T) {
	_, err := NewGitHubAppSource("1", "2", []byte("not a pem"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestGitHubAppSource_NonRSAKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	_, err = NewGitHubAppSource("1", "2", keyPEM)
	if err == nil {
		t.Fatal("expected error for non-RSA key")
	}
}

func TestGitHubAppSource_APIError(t *testing.T) {
	_, keyPEM := generateTestKey(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer srv.Close()

	src, _ := NewGitHubAppSource("1", "2", keyPEM)
	src.apiBaseURL = srv.URL

	_, err := src.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error = %q, want to contain 401", err)
	}
}

func TestGitHubAppSource_MalformedJSON(t *testing.T) {
	_, keyPEM := generateTestKey(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{not json`))
	}))
	defer srv.Close()

	src, _ := NewGitHubAppSource("1", "2", keyPEM)
	src.apiBaseURL = srv.URL

	_, err := src.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestGitHubAppSource_MissingToken(t *testing.T) {
	_, keyPEM := generateTestKey(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
		})
	}))
	defer srv.Close()

	src, _ := NewGitHubAppSource("1", "2", keyPEM)
	src.apiBaseURL = srv.URL

	_, err := src.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error for missing token field")
	}
}

func TestGitHubAppSource_MissingExpiresAt(t *testing.T) {
	_, keyPEM := generateTestKey(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"token": "ghs_abc",
		})
	}))
	defer srv.Close()

	src, _ := NewGitHubAppSource("1", "2", keyPEM)
	src.apiBaseURL = srv.URL

	_, err := src.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error for missing expires_at field")
	}
}

func TestGitHubAppSource_LenientPKCS1Key(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der := x509.MarshalPKCS1PrivateKey(key)

	// Corrupt the CRT parameter q (prime2) so p*q != n, simulating keys
	// that work in OpenSSL-based runtimes but fail Go's strict validation.
	var raw struct {
		Version int
		N       *big.Int
		E       int
		D       *big.Int
		P       *big.Int
		Q       *big.Int
		Dp      *big.Int
		Dq      *big.Int
		Qinv    *big.Int
	}
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		t.Fatal(err)
	}
	raw.Q = new(big.Int).Add(raw.Q, big.NewInt(2))
	corruptDER, err := asn1.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: corruptDER})

	// Standard Go parser would reject this key; lenient parser should accept it.
	src, err := NewGitHubAppSource("1", "2", keyPEM)
	if err != nil {
		t.Fatalf("NewGitHubAppSource with corrupt CRT params: %v", err)
	}
	if src.Type() != "github-app" {
		t.Errorf("Type() = %q, want github-app", src.Type())
	}

	// Verify the key can still sign — the original N, E, D are intact.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"token":      "ghs_lenient",
			"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		})
	}))
	defer srv.Close()
	src.apiBaseURL = srv.URL

	token, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch with lenient key: %v", err)
	}
	if token != "ghs_lenient" {
		t.Errorf("token = %q, want ghs_lenient", token)
	}
}

func TestGitHubAppSource_PKCS8Key(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	src, err := NewGitHubAppSource("1", "2", keyPEM)
	if err != nil {
		t.Fatalf("NewGitHubAppSource with PKCS8: %v", err)
	}
	if src.Type() != "github-app" {
		t.Errorf("Type() = %q, want github-app", src.Type())
	}
}
