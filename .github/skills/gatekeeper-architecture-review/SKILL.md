---
name: gatekeeper-architecture-review
description: Gatekeeper-specific checks for the shared architecture-review skill: proxy authentication, credential injection, the MITM CA, token exchange, and the library boundary. Apply to every pull request, alongside the correctness review.
---

# Gatekeeper architecture checks

Apply the installed shared skills first: `.agents/skills/architecture-review/SKILL.md` for the review method and questions, and `.agents/skills/go-guide/SKILL.md` for Go layout, API, and test rules. This file adds only what is specific to gatekeeper. If this file and the docs disagree, the docs win and this file is the bug.

## Where the architecture is written

Gatekeeper has no single spec file. Read the section that the change touches:

- Root `AGENTS.md`: `Architecture`, `Key Types`, `How Credential Injection Works`, `Security Considerations`.
- `docs/content/concepts/`: TLS interception, credential injection, credential sources, network policy, MCP relay, observability, host gateway, Postgres data plane.
- `docs/content/reference/02-config-file.md`: the config contract, including `proxy.auth_token`.
- `docs/token-exchange-endpoint.md`: the contract with the STS that gatekeeper calls.

If a file is not in your checkout, say so. Do not guess its content. Cite the doc as `path:line`.

## Gatekeeper questions

A "yes" is a finding.

1. **Credential exposure.** Can a credential value reach a log line, span attribute, metric label, error returned to a client, response body, or temp file? Logs name the host and grant only.
2. **Proxy authentication.** Does a path skip `Proxy-Authorization` checks? Check CONNECT, plain HTTP, `/relay/`, and the Postgres listener. A mismatched password gets `407` before any resolver or STS call. The token comparison is constant-time. A `407` with a missing and with a wrong password has the same body.
3. **Injection scope.** Does a credential match a host by anything other than exact name or an explicit glob? Is the host compared after port stripping and case folding? Can a client-supplied header replace or keep an injected credential?
4. **MITM CA.** Does the CA private key stay in memory? Does the change write it to a file, log it, or pass it across a process boundary? Can a malformed CONNECT bypass interception?
5. **Token exchange.** Does the subject come only from the configured source (`subject_from` or `subject_header`), never from a header an untrusted caller sets under proxy-auth mode? Is the actor token forwarded only when `actor_token_from` is set? Does a bot or empty subject skip the STS round trip? Do the wire fields match `docs/token-exchange-endpoint.md`?
6. **Source ownership.** Does each credential backend implement `credentialsource.CredentialSource` or `RefreshingSource`? Is the proxy core free of backend branches? Do identical `source` blocks still share one fetch and one refresh goroutine?
7. **Library boundary.** Does the change add an `internal/` package, or make `proxy/` know about moat? Gatekeeper is an importable module. A public API or YAML field change is a contract change: it needs a doc update and a `CHANGELOG.md` entry that names the behavior change.
8. **Observability stays additive.** Does `proxy/proxy.go` import OTel? Instrumentation attaches through callbacks and `proxy/otel.go`, and must not change request behavior or errors.
9. **Fail-open and fail-closed.** Does a new error path open a connection that policy should block? PROXY protocol parsing stays fail-open on headerless connections only. Network policy and auth stay fail-closed.
10. **Tests.** A bug fix has a regression test that failed first and names the real values from the report. A security change has a test for the rejected input, not only the accepted one.

## Reporting

Follow the `Reporting` section of the shared `architecture-review` skill. Block on questions 1 to 5 whenever the answer is yes.
