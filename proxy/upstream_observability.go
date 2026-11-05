package proxy

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

func captureUpstreamAuthCode(resp *http.Response) *capturingBody {
	if resp.StatusCode != http.StatusUnauthorized || resp.Body == nil || !isTextContentType(resp.Header.Get("Content-Type")) {
		return nil
	}
	body := newCapturingBody(resp.Body, MaxBodySize, nil)
	resp.Body = body
	return body
}

func upstreamAuthCode(body *capturingBody, headers http.Header, injected []CredentialHeader, substitution bool) string {
	if body == nil || substitution {
		return ""
	}
	var data struct {
		Detail struct {
			Code string `json:"code"`
		} `json:"detail"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body.Captured(), &data) != nil {
		return ""
	}
	code := data.Detail.Code
	if code == "" {
		code = data.Error.Code
	}
	if len(code) == 0 || len(code) > 64 {
		return ""
	}
	for i, c := range code {
		if !(c >= 'a' && c <= 'z' || i > 0 && (c >= '0' && c <= '9' || c == '_')) {
			return ""
		}
	}
	for _, cred := range injected {
		if overlapsCredential(code, cred.Value) {
			return ""
		}
	}
	for _, values := range headers {
		for _, value := range values {
			if overlapsCredential(code, value) {
				return ""
			}
			for _, part := range strings.Fields(value) {
				if overlapsCredential(code, part) {
					return ""
				}
			}
		}
	}
	return code
}

func overlapsCredential(code, value string) bool {
	if value == "" {
		return false
	}
	if strings.Contains(value, code) || strings.Contains(code, value) {
		return true
	}
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return true
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return true
	}
	return overlapsCredential(code, username) || overlapsCredential(code, password)
}
