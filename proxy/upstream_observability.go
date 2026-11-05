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
		if overlapsCredential(code, cred.Value, strings.EqualFold(cred.Name, "Authorization")) {
			return ""
		}
	}
	for name, values := range headers {
		credential := !strings.EqualFold(name, "Accept-Language")
		for _, cred := range injected {
			if strings.EqualFold(name, cred.Name) {
				credential = true
				break
			}
		}
		for _, value := range values {
			if credential {
				if overlapsCredential(code, value, strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Proxy-Authorization")) {
					return ""
				}
			} else if strings.Contains(value, code) {
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
	if strings.Contains(value, code) || strings.Contains(code, value) {
		return true
	}
	parts := strings.Fields(value)
	if authorization && len(parts) == 2 {
		scheme := parts[0]
		if strings.EqualFold(scheme, "Basic") {
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
		if strings.EqualFold(scheme, "Bearer") || strings.EqualFold(scheme, "token") {
			parts = parts[1:]
		}
	}
	for _, part := range parts {
		if strings.Contains(part, code) || strings.Contains(code, part) {
			return true
		}
	}
	return false
}
