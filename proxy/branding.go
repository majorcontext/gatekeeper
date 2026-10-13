package proxy

import "net/http"

const (
	defaultBrandName     = "gatekeeper"
	defaultMCPStubPrefix = "gatekeeper-stub-"
	defaultPolicyScheme  = "Gatekeeper-Policy"
)

// Branding sets the client-visible wording of blocked responses and relay
// errors. The zero value is neutral; an embedder sets only what it wants to
// phrase differently.
type Branding struct {
	// Name prefixes block messages ("<Name>: request blocked ..."). Default "gatekeeper".
	Name string
	// ErrorPrefix prefixes relay and MCP error bodies. Default: Name.
	ErrorPrefix string
	// MCPStubPrefix starts the placeholder value that stands in for an MCP
	// credential in client config. Default "gatekeeper-stub-".
	MCPStubPrefix string
	// PolicyScheme is the Proxy-Authenticate scheme on blocked responses.
	// Default "Gatekeeper-Policy".
	PolicyScheme string
	// NetworkHint is appended to a network-policy block message.
	NetworkHint string
	// HostHint returns text appended to a host-service block message.
	HostHint func(port int) string
	// GrantHint returns text appended when an MCP credential cannot be loaded.
	GrantHint func(grant string) string
}

// SetBranding replaces the proxy's client-visible wording. Call it before
// serving.
func (p *Proxy) SetBranding(b Branding) {
	p.branding = b
}

func (p *Proxy) brandName() string {
	if p.branding.Name != "" {
		return p.branding.Name
	}
	return defaultBrandName
}

func (p *Proxy) errorPrefix() string {
	if p.branding.ErrorPrefix != "" {
		return p.branding.ErrorPrefix
	}
	return p.brandName()
}

func (p *Proxy) mcpStubPrefix() string {
	if p.branding.MCPStubPrefix != "" {
		return p.branding.MCPStubPrefix
	}
	return defaultMCPStubPrefix
}

func (p *Proxy) policyScheme() string {
	if p.branding.PolicyScheme != "" {
		return p.branding.PolicyScheme
	}
	return defaultPolicyScheme
}

func (p *Proxy) grantHint(grant string) string {
	if p.branding.GrantHint == nil {
		return ""
	}
	return p.branding.GrantHint(grant)
}

func (p *Proxy) hostHint(port int) string {
	if p.branding.HostHint == nil {
		return ""
	}
	if hint := p.branding.HostHint(port); hint != "" {
		return hint + "\n"
	}
	return ""
}

func (p *Proxy) networkHint() string {
	if p.branding.NetworkHint == "" {
		return ""
	}
	return p.branding.NetworkHint + "\n"
}

// setBlocked marks a response as policy-blocked. X-Moat-Blocked carries the
// same value for legacy clients.
func setBlocked(h http.Header, reason string) {
	h.Set("X-Gatekeeper-Blocked", reason)
	h.Set("X-Moat-Blocked", reason)
}
