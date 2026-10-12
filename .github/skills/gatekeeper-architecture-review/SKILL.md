---
name: gatekeeper-architecture-review
description: Gatekeeper-specific checks for the shared architecture-review skill, covering proxy authentication, credential injection, the MITM CA, token exchange, and the library boundary. Apply to every pull request, alongside the correctness review.
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
2. **Proxy authentication.** On the HTTP paths (CONNECT, plain HTTP, `/relay/`), can a password that does not constant-time-equal a configured `auth_token` reach a resolver or the STS before the `407`? Does a `407` for a wrong password differ in body from one for no credentials? On the Postgres listener, does the run-token compare in `PostgresServer.authenticate` stop being constant-time, or fail with anything other than a Postgres `ErrorResponse`?
3. **Injection scope.** Does a credential match a host by anything other than exact name or an explicit glob? Is the host compared before port stripping or case folding? Can a client-supplied header replace or keep an injected credential?
4. **MITM CA.** Does the change write the CA private key anywhere other than the `0600` `ca.key` that `proxy.NewCA` creates, log it, or widen its file mode? Can a malformed CONNECT bypass interception?
5. **Token exchange.** Can the subject come from anything other than the configured source (`subject_from` or `subject_header`), such as a header an untrusted caller sets under proxy-auth mode? Is the actor token forwarded when `actor_token_from` is unset? Does a bot or empty subject still call the STS? Does a wire field differ from `docs/token-exchange-endpoint.md`?
6. **Source ownership.** Does a credential backend bypass `credentialsource.CredentialSource` or `RefreshingSource`? Does the proxy core branch on a backend type? Do identical `source` blocks now fetch more than once or start a second refresh goroutine?
7. **Library boundary.** Does the change add an `internal/` package, or make `proxy/` know about moat? Gatekeeper is an importable module. A public API or YAML field change is a contract change: it needs a doc update and a `CHANGELOG.md` entry that names the behavior change.
8. **Observability stays additive.** Does `proxy/proxy.go` import OTel? Instrumentation attaches through callbacks and `proxy/otel.go`, and must not change request behavior or errors.
9. **Fail-open and fail-closed.** Does a new error path open a connection that policy should block? PROXY protocol parsing stays fail-open on headerless connections only. Network policy and auth stay fail-closed.
10. **Tests.** Does a bug fix lack a regression test that failed first and names the real values from the report? Does a security change test only the accepted input and not the rejected one?

## Reporting

Follow the `Reporting` section of the shared `architecture-review` skill. Block on questions 1 to 5 whenever the answer is yes.
