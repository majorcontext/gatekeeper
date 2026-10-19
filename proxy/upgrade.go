package proxy

import (
	"io"
	"net/http"
	"slices"
	"strings"
)

// UpgradeHintHeader carries an UpgradeHint to the client on a 401 or 403
// response, as an RFC 9651 dictionary whose members are inner lists of
// strings. The proxy removes any value the upstream sends.
const UpgradeHintHeader = "X-Gatekeeper-Upgrade"

// maxUpgradeHintHeaderLen bounds UpgradeHintHeader. A longer hint is dropped
// whole: a header past the client's limit would break the 401 or 403
// response it rides on.
const maxUpgradeHintHeaderLen = 1024

// UpgradeHint is what a credential resolver reports the client could request
// beyond the credential the request got. Each key maps to one or more values.
type UpgradeHint map[string][]string

// ResolverDeclined is the error a CredentialResolver returns when it has no
// credential for the request and the host's static credentials apply.
type ResolverDeclined struct {
	UpgradeHint UpgradeHint
	// Invalidate, when non-nil, drops the cached decline. The proxy calls it
	// on the same statuses as CredentialHeader.Invalidate, so a credential
	// granted since the decline applies to the client's retry.
	Invalidate func()
}

func (*ResolverDeclined) Error() string {
	return "credential resolver declined: use the static credentials"
}

// resolvedCredentials is the outcome of credential lookup for one request.
type resolvedCredentials struct {
	creds []CredentialHeader
	// declined is set when the host's resolver deferred to creds.
	declined *ResolverDeclined
}

// settleUpstreamResponse evicts the cached state behind a request the
// destination rejected, and sets the upgrade hint on resp for a 401 or 403.
// injected holds the credentials actually sent.
func settleUpstreamResponse(resp *http.Response, injected []CredentialHeader, declined *ResolverDeclined) {
	h, status := resp.Header, resp.StatusCode
	h.Del(UpgradeHintHeader)
	scrubHintTrailer(resp)
	invalidateCredentialsOnCredentialFailure(injected, status)
	if declined != nil && declined.Invalidate != nil && isCredentialFailure(status) {
		declined.Invalidate()
	}
	if status != http.StatusUnauthorized && status != http.StatusForbidden {
		return
	}
	var v string
	if declined != nil {
		v = declined.UpgradeHint.headerValue()
	}
	for i := 0; v == "" && i < len(injected); i++ {
		v = injected[i].UpgradeHint.headerValue()
	}
	if v != "" {
		h.Set(UpgradeHintHeader, v)
	}
}

// scrubHintTrailer removes UpgradeHintHeader from resp's trailers, both the
// announced ones and those the transport merges in at EOF, announced or not.
// A 101 body is left alone: it must stay an io.ReadWriteCloser.
func scrubHintTrailer(resp *http.Response) {
	resp.Trailer.Del(UpgradeHintHeader)
	if resp.Body == nil || resp.StatusCode == http.StatusSwitchingProtocols {
		return
	}
	resp.Body = &hintTrailerScrubber{ReadCloser: resp.Body, resp: resp}
}

type hintTrailerScrubber struct {
	io.ReadCloser
	resp *http.Response
}

func (s *hintTrailerScrubber) Read(p []byte) (int, error) {
	n, err := s.ReadCloser.Read(p)
	if err == io.EOF {
		s.resp.Trailer.Del(UpgradeHintHeader)
	}
	return n, err
}

// headerValue serializes h as an RFC 9651 dictionary with sorted members. A
// member whose key is not an sf-key, or with a value that is not printable
// ASCII, is dropped, so a hint can never inject a header. A result longer
// than maxUpgradeHintHeaderLen is dropped.
func (h UpgradeHint) headerValue() string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var members []string
	for _, k := range keys {
		if !isSFKey(k) || len(h[k]) == 0 {
			continue
		}
		items := make([]string, 0, len(h[k]))
		for _, v := range h[k] {
			s, ok := sfString(v)
			if !ok {
				items = nil
				break
			}
			items = append(items, s)
		}
		if items != nil {
			members = append(members, k+"=("+strings.Join(items, " ")+")")
		}
	}
	v := strings.Join(members, ", ")
	if len(v) > maxUpgradeHintHeaderLen {
		return ""
	}
	return v
}

func isSFKey(k string) bool {
	if k == "" || !(k[0] == '*' || 'a' <= k[0] && k[0] <= 'z') {
		return false
	}
	for i := 1; i < len(k); i++ {
		c := k[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || strings.IndexByte("_-.*", c) >= 0) {
			return false
		}
	}
	return true
}

func sfString(v string) (string, bool) {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c < 0x20 || c > 0x7e {
			return "", false
		}
		if c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	b.WriteByte('"')
	return b.String(), true
}
