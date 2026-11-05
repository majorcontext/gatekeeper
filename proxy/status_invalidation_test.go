package proxy

import (
	"net/http"
	"testing"
)

func TestStatusAwareInvalidation(t *testing.T) {
	var got, legacy int
	cred := CredentialHeader{
		Invalidate:           func() { legacy++ },
		InvalidateWithStatus: func(status int) { got = status },
	}
	invalidateCredentialsOnCredentialFailure([]CredentialHeader{cred}, http.StatusForbidden)
	if got != http.StatusForbidden || legacy != 0 {
		t.Fatalf("status = %d, legacy calls = %d; want %d, 0", got, legacy, http.StatusForbidden)
	}

	cred.InvalidateWithStatus = nil
	invalidateCredentialsOnCredentialFailure([]CredentialHeader{cred}, http.StatusUnauthorized)
	if legacy != 1 {
		t.Fatalf("legacy calls = %d; want 1", legacy)
	}
}
