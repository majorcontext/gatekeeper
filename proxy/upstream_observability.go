package proxy

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

func captureUpstreamAuthCode(resp *http.Response, req *http.Request) *capturingBody {
	if req == nil || req.URL == nil || req.URL.User != nil || req.URL.RawQuery != "" || req.URL.ForceQuery {
		return nil
	}
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
		Detail json.RawMessage `json:"detail"`
		Error  json.RawMessage `json:"error"`
	}
	if json.Unmarshal(body.Captured(), &data) != nil {
		return ""
	}
	parseCode := func(raw json.RawMessage) string {
		var field struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(raw, &field) != nil {
			return ""
		}
		return field.Code
	}
	code := parseCode(data.Detail)
	if code == "" {
		code = parseCode(data.Error)
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
		if overlapsCredential(code, cred.Value, strings.EqualFold(cred.Name, "Authorization")) {
			return ""
		}
	}
	for name, values := range headers {
		for _, value := range values {
			if overlapsCredential(code, value, strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Proxy-Authorization")) {
				return ""
			}
		}
	}
	return code
}

func overlapsCredential(code, value string, authorization bool) bool {
	if value == "" {
		return false
	}
	if len(value) > MaxBodySize {
		return true
	}
	lowerValue := strings.ToLower(value)
	if strings.Contains(lowerValue, code) || strings.Contains(code, lowerValue) {
		return true
	}
	parts := strings.Fields(value)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Basic") {
		if credentialFragmentOverlap(code, parts[1]) {
			return true
		}
		decoded, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return true
		}
		username, password, ok := strings.Cut(string(decoded), ":")
		if !ok {
			return true
		}
		return overlapsCredential(code, username, false) || overlapsCredential(code, password, false)
	}
	if authorization && len(parts) == 2 && (strings.EqualFold(parts[0], "Bearer") || strings.EqualFold(parts[0], "token")) {
		parts = parts[1:]
	}
	for _, part := range parts {
		if credentialFragmentOverlap(code, part) {
			return true
		}
	}
	return false
}

func credentialFragmentOverlap(code, value string) bool {
	value = strings.ToLower(value)
	if strings.Contains(value, code) || strings.Contains(code, value) {
		return true
	}
	const fragmentSize = 8
	for i := 0; i+fragmentSize <= len(code); i++ {
		if strings.Contains(value, code[i:i+fragmentSize]) {
			return true
		}
	}
	return false
}
