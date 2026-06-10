package credentialsource

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testSAKeyJSON builds a GCP service account key JSON for the given RSA key,
// with token_uri pointing at tokenURI. Mirrors the real key file format:
// PKCS#8 PEM private key, client_email, token_uri.
func testSAKeyJSON(t *testing.T, key *rsa.PrivateKey, tokenURI string) []byte {
	t.Helper()
	return testSAKeyJSONWithEmail(t, key, tokenURI, "uploader@my-project.iam.gserviceaccount.com")
}

func testSAKeyJSONWithEmail(t *testing.T, key *rsa.PrivateKey, tokenURI, email string) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	b, err := json.Marshal(map[string]string{
		"type":         "service_account",
		"client_email": email,
		"private_key":  string(keyPEM),
		"token_uri":    tokenURI,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// jwtClaims extracts the claims map from a JWT assertion in a request form.
func jwtClaims(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	if err := r.ParseForm(); err != nil {
		t.Fatalf("parsing form: %v", err)
	}
	parts := splitJWT(t, r.PostForm.Get("assertion"))
	var claims map[string]any
	if err := json.Unmarshal(decodeBase64URL(t, parts[1]), &claims); err != nil {
		t.Fatalf("decoding claims: %v", err)
	}
	return claims
}

func TestGCPServiceAccountSource_JWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	var gotGrantType, gotAssertion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parsing form: %v", err)
		}
		gotGrantType = r.PostForm.Get("grant_type")
		gotAssertion = r.PostForm.Get("assertion")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "ya29.test-token",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	}))
	defer srv.Close()

	src, err := NewGCPServiceAccountSource(testSAKeyJSON(t, key, srv.URL), "https://www.googleapis.com/auth/devstorage.read_write")
	if err != nil {
		t.Fatalf("NewGCPServiceAccountSource: %v", err)
	}

	token, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if token != "ya29.test-token" {
		t.Errorf("token = %q, want ya29.test-token", token)
	}

	if gotGrantType != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		t.Errorf("grant_type = %q, want jwt-bearer grant", gotGrantType)
	}

	parts := splitJWT(t, gotAssertion)

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
	if claims["iss"] != "uploader@my-project.iam.gserviceaccount.com" {
		t.Errorf("JWT iss = %v, want client_email", claims["iss"])
	}
	if claims["scope"] != "https://www.googleapis.com/auth/devstorage.read_write" {
		t.Errorf("JWT scope = %v, want devstorage.read_write", claims["scope"])
	}
	if claims["aud"] != srv.URL {
		t.Errorf("JWT aud = %v, want %s", claims["aud"], srv.URL)
	}
	iat := int64(claims["iat"].(float64))
	exp := int64(claims["exp"].(float64))
	now := time.Now().Unix()
	if iat > now-5 || iat < now-120 {
		t.Errorf("JWT iat = %d, want ~%d (backdated ~10s for clock skew)", iat, now-10)
	}
	if exp-iat != 3600 {
		t.Errorf("JWT exp-iat = %d, want 3600", exp-iat)
	}

	verifyRS256(t, parts[0]+"."+parts[1], parts[2], &key.PublicKey)
}

func TestGCPServiceAccountSource_FetchAndTTL(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "ya29.abc",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	src, err := NewGCPServiceAccountSource(testSAKeyJSON(t, key, srv.URL), "")
	if err != nil {
		t.Fatalf("NewGCPServiceAccountSource: %v", err)
	}

	if src.Type() != "gcp-service-account" {
		t.Errorf("Type() = %q, want gcp-service-account", src.Type())
	}
	if ttl := src.TTL(); ttl != 0 {
		t.Errorf("TTL before Fetch = %v, want 0", ttl)
	}

	token, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if token != "ya29.abc" {
		t.Errorf("token = %q, want ya29.abc", token)
	}

	ttl := src.TTL()
	if ttl < 59*time.Minute || ttl > 60*time.Minute {
		t.Errorf("TTL = %v, want ~1h", ttl)
	}
}

func TestGCPServiceAccountSource_DefaultScope(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	var gotScope string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotScope, _ = jwtClaims(t, r)["scope"].(string)
		json.NewEncoder(w).Encode(map[string]any{"access_token": "ya29.x", "expires_in": 3600})
	}))
	defer srv.Close()

	src, err := NewGCPServiceAccountSource(testSAKeyJSON(t, key, srv.URL), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if gotScope != "https://www.googleapis.com/auth/cloud-platform" {
		t.Errorf("scope = %q, want cloud-platform default", gotScope)
	}
}

func TestGCPServiceAccountSource_InvalidKeyJSON(t *testing.T) {
	if _, err := NewGCPServiceAccountSource([]byte("not json"), ""); err == nil {
		t.Fatal("expected error for invalid key JSON")
	}
}

func TestGCPServiceAccountSource_WrongKeyType(t *testing.T) {
	_, err := NewGCPServiceAccountSource([]byte(`{"type":"authorized_user","client_email":"e","private_key":"k"}`), "")
	if err == nil {
		t.Fatal("expected error for non-service_account key type")
	}
}

func TestGCPServiceAccountSource_MissingFields(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"missing client_email", `{"type":"service_account","private_key":"k"}`},
		{"missing private_key", `{"type":"service_account","client_email":"e"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewGCPServiceAccountSource([]byte(tt.json), ""); err == nil {
				t.Fatal("expected error for missing field")
			}
		})
	}
}

func TestGCPServiceAccountSource_InvalidPEM(t *testing.T) {
	b, _ := json.Marshal(map[string]string{
		"type":         "service_account",
		"client_email": "e@p.iam.gserviceaccount.com",
		"private_key":  "not a pem",
	})
	if _, err := NewGCPServiceAccountSource(b, ""); err == nil {
		t.Fatal("expected error for invalid PEM private key")
	}
}

func TestGCPServiceAccountSource_TokenEndpointError(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()

	src, err := NewGCPServiceAccountSource(testSAKeyJSON(t, key, srv.URL), "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = src.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error = %q, want to contain 401", err)
	}
}

func TestGCPServiceAccountSource_MissingExpiresIn(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "ya29.x"})
	}))
	defer srv.Close()

	src, err := NewGCPServiceAccountSource(testSAKeyJSON(t, key, srv.URL), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Fetch(context.Background()); err == nil {
		t.Fatal("expected error for missing expires_in (would cause refresh loop to re-mint every 30s)")
	}
}

func TestGCPServiceAccountSource_MissingAccessToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"expires_in": 3600})
	}))
	defer srv.Close()

	src, err := NewGCPServiceAccountSource(testSAKeyJSON(t, key, srv.URL), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Fetch(context.Background()); err == nil {
		t.Fatal("expected error for missing access_token")
	}
}

// fakeKeySource is a CredentialSource that returns a fixed key JSON and
// counts fetches, for testing lazy key loading.
type fakeKeySource struct {
	val     string
	err     error
	fetches int
	closed  bool
}

func (f *fakeKeySource) Fetch(ctx context.Context) (string, error) {
	f.fetches++
	if f.err != nil {
		return "", f.err
	}
	return f.val, nil
}

func (f *fakeKeySource) Type() string { return "fake" }

func (f *fakeKeySource) Close() error {
	f.closed = true
	return nil
}

func TestGCPServiceAccountSource_FromKeySource(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "ya29.lazy", "expires_in": 3600})
	}))
	defer srv.Close()

	ks := &fakeKeySource{val: string(testSAKeyJSON(t, key, srv.URL))}
	src := NewGCPServiceAccountSourceFromKeySource(ks, "")

	for i := range 3 {
		token, err := src.Fetch(context.Background())
		if err != nil {
			t.Fatalf("Fetch #%d: %v", i+1, err)
		}
		if token != "ya29.lazy" {
			t.Errorf("token = %q, want ya29.lazy", token)
		}
	}
	if ks.fetches != 1 {
		t.Errorf("key source fetches = %d, want 1 (key should be cached)", ks.fetches)
	}

	if err := src.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !ks.closed {
		t.Error("Close did not propagate to key source")
	}
}

func TestGCPServiceAccountSource_KeyRotation(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// The endpoint rejects assertions from the old (revoked) key's identity.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if iss, _ := jwtClaims(t, r)["iss"].(string); iss != "new@p.iam.gserviceaccount.com" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "ya29.rotated", "expires_in": 3600})
	}))
	defer srv.Close()

	ks := &fakeKeySource{val: string(testSAKeyJSONWithEmail(t, oldKey, srv.URL, "old@p.iam.gserviceaccount.com"))}
	src := NewGCPServiceAccountSourceFromKeySource(ks, "")

	// First fetch uses the old key and is rejected.
	if _, err := src.Fetch(context.Background()); err == nil {
		t.Fatal("expected error for revoked key")
	}

	// The key is rotated in the key source (e.g., a new Secret Manager
	// version). The next fetch must re-read the key rather than reuse
	// the rejected cached one.
	ks.val = string(testSAKeyJSONWithEmail(t, newKey, srv.URL, "new@p.iam.gserviceaccount.com"))
	token, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch after rotation: %v", err)
	}
	if token != "ya29.rotated" {
		t.Errorf("token = %q, want ya29.rotated", token)
	}
	if ks.fetches != 2 {
		t.Errorf("key source fetches = %d, want 2 (re-fetch after rejection)", ks.fetches)
	}
}

func TestGCPServiceAccountSource_KeySourceError(t *testing.T) {
	ks := &fakeKeySource{err: context.DeadlineExceeded}
	src := NewGCPServiceAccountSourceFromKeySource(ks, "")
	if _, err := src.Fetch(context.Background()); err == nil {
		t.Fatal("expected error when key source fails")
	}
}
