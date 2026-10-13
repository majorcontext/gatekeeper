package credentialsource

import (
	"fmt"
	"io"
	"net/http"
)

// readTokenResponse reads up to 64KB of resp's body. When the status is not
// wantStatus, it returns an error naming label with a truncated response
// body for context.
func readTokenResponse(resp *http.Response, wantStatus int, label string) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if resp.StatusCode != wantStatus {
		msg := string(body)
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, fmt.Errorf("%s returned %d: %s", label, resp.StatusCode, msg)
	}
	return body, nil
}
