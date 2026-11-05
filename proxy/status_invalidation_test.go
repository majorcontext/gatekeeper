package proxy

import (
	"net/http"
	"testing"
)

func TestStatusAwareInvalidation(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests, http.StatusOK} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var got, legacy int
			cred := CredentialHeader{Invalidate: func() { legacy++ }, InvalidateWithStatus: func(status int) { got = status }}
			invalidateCredentialsOnCredentialFailure([]CredentialHeader{cred}, status)
			want := status
			if status == http.StatusOK {
				want = 0
			}
			if got != want || legacy != 0 {
				t.Fatalf("status = %d, legacy calls = %d; want %d, 0", got, legacy, want)
			}
			invalidateCredentialsOnCredentialFailure([]CredentialHeader{{Invalidate: func() { legacy++ }}}, status)
			wantLegacy := 1
			if status == http.StatusOK {
				wantLegacy = 0
			}
			if legacy != wantLegacy {
				t.Fatalf("legacy calls = %d, want %d", legacy, wantLegacy)
			}
		})
	}
}
