// Package proxy provides a TLS-intercepting HTTP proxy for credential injection.
//
// # Security Model
//
// The proxy intercepts HTTPS traffic via CONNECT tunneling with dynamic certificate
// generation. It injects credentials (Authorization headers, etc.) for configured
// hosts without exposing raw tokens to the container.
//
// # Firewall Integration
//
// Container firewall rules (iptables) work in conjunction with the proxy:
//
//   - Docker: Proxy binds to 127.0.0.1 (localhost only). Containers reach it via
//     host.docker.internal or host network mode. Firewall allows proxy port only.
//
//   - Apple containers: Proxy binds to 0.0.0.0 with per-run token authentication.
//     Security is maintained via cryptographic tokens in HTTP_PROXY URL, not IP filtering.
//
// The firewall rules intentionally do NOT filter by destination IP for the proxy port.
// This is because host.docker.internal resolves to different IPs across environments.
// The security boundaries are:
//
//  1. Random high port assignment (reduces collision with other services)
//  2. Token authentication for Apple containers
//  3. Container isolation (other containers can't reach host ports by default)
//
// This trade-off prioritizes reliability over defense-in-depth. The proxy validates
// credentials are only injected for explicitly configured hosts.
package proxy
