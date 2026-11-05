package proxy

import (
	"net/http"
	"testing"
)

func TestStatusAwareInvalidation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		statusAware bool
	}{
		{"status-aware takes precedence", http.StatusForbidden, true},
		{"legacy fallback", http.StatusUnauthorized, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got, legacy int
			cred := CredentialHeader{Invalidate: func() { legacy++ }}
			if tc.statusAware {
				cred.InvalidateWithStatus = func(status int) { got = status }
			}
			invalidateCredentialsOnCredentialFailure([]CredentialHeader{cred}, tc.status)
			if tc.statusAware {
				if got != tc.status || legacy != 0 {
					t.Fatalf("status = %d, legacy calls = %d; want %d, 0", got, legacy, tc.status)
				}
			} else if got != 0 || legacy != 1 {
				t.Fatalf("status = %d, legacy calls = %d; want 0, 1", got, legacy)
			}
		})
	}
}
