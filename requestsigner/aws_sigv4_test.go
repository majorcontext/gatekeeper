package requestsigner

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

func TestNewAWSSigV4SignerValidation(t *testing.T) {
	_, err := NewAWSSigV4SignerWithStaticCredentials("AKID", "secret", "", "bedrock")
	if err == nil {
		t.Fatal("expected error for empty region")
	}
	_, err = NewAWSSigV4SignerWithStaticCredentials("AKID", "secret", "us-east-1", "")
	if err == nil {
		t.Fatal("expected error for empty service")
	}
}

func TestNewAWSSigV4SignerDefaultChainValidation(t *testing.T) {
	_, err := NewAWSSigV4Signer("", "bedrock")
	if err == nil {
		t.Fatal("expected error for empty region")
	}
	_, err = NewAWSSigV4Signer("us-east-1", "")
	if err == nil {
		t.Fatal("expected error for empty service")
	}
}

func TestSignRequestWithStaticCredentials(t *testing.T) {
	signer, err := NewAWSSigV4SignerWithStaticCredentials(
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"us-east-1",
		"bedrock",
	)
	if err != nil {
		t.Fatalf("NewAWSSigV4SignerWithStaticCredentials: %v", err)
	}

	req, _ := http.NewRequest("POST", "https://bedrock-runtime.us-east-1.amazonaws.com/model/invoke", nil)
	if err := signer.SignRequest(context.Background(), req); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	if req.Header.Get("Authorization") == "" {
		t.Error("expected Authorization header after signing")
	}
	if req.Header.Get("X-Amz-Date") == "" {
		t.Error("expected X-Amz-Date header after signing")
	}

	auth := req.Header.Get("Authorization")
	if auth == "" {
		t.Fatal("empty Authorization")
	}
	if !bytes.Contains([]byte(auth), []byte("AWS4-HMAC-SHA256")) {
		t.Errorf("Authorization header doesn't contain SigV4 prefix: %s", auth)
	}
	if !bytes.Contains([]byte(auth), []byte("bedrock")) {
		t.Errorf("Authorization header doesn't contain service name: %s", auth)
	}
}

func TestSignRequestWithBody(t *testing.T) {
	signer, err := NewAWSSigV4SignerWithStaticCredentials(
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"us-east-1",
		"bedrock",
	)
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"prompt": "hello"}`)
	req, _ := http.NewRequest("POST",
		"https://bedrock-runtime.us-east-1.amazonaws.com/model/invoke",
		bytes.NewReader(body))
	req.ContentLength = int64(len(body))

	if err := signer.SignRequest(context.Background(), req); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	// Body should still be readable after signing.
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading body after sign: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("body after signing = %q, want %q", got, body)
	}

	// The Authorization header should contain a valid SigV4 signature
	// that was computed from the hashed body (not UNSIGNED-PAYLOAD).
	auth := req.Header.Get("Authorization")
	if !bytes.Contains([]byte(auth), []byte("AWS4-HMAC-SHA256")) {
		t.Errorf("Authorization header doesn't contain SigV4 prefix: %s", auth)
	}
}
