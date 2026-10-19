package credentialsource

import (
	"fmt"
	"io"
	"net/http"
)

// maxTokenResponseSize bounds how much of a token endpoint response is read.
const maxTokenResponseSize = 64 * 1024

// readTokenResponse reads up to 64KB of resp's body. When the status is not
// wantStatus, it returns an error naming label with a truncated response
// body for context.
func readTokenResponse(resp *http.Response, wantStatus int, label string) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseSize))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if resp.StatusCode != wantStatus {
		return nil, tokenResponseError(label, resp.StatusCode, body)
	}
	return body, nil
}

func tokenResponseError(label string, status int, body []byte) error {
	msg := string(body)
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return fmt.Errorf("%s returned %d: %s", label, status, msg)
}
