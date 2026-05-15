# Documentation Style Guide

This guide establishes the voice, tone, and conventions for Gatekeeper documentation. Follow these guidelines to ensure consistency across all pages.

## Voice and Tone

### Be Objective
State facts. Avoid hyperbole, marketing language, and subjective claims.

| Avoid | Prefer |
|-------|--------|
| "Gatekeeper makes credential management incredibly easy" | "Gatekeeper injects credentials at the network layer" |
| "The blazingly fast proxy" | "The proxy adds ~2ms latency per request" |
| "Finally, a solution that actually works" | (Just describe what it does) |
| "Unlike other tools that get this wrong..." | (Describe Gatekeeper's approach without comparison) |

Don't use words like: revolutionary, game-changing, seamless, effortless, simple (as a claim), easy (as a claim), powerful, robust, elegant, beautiful, magic/magical.

### Be Respectful
Acknowledge that other tools exist and serve their purposes. Avoid dismissive comparisons.

When comparing approaches, describe what Gatekeeper does and let readers draw their own conclusions. Don't tell them what's wrong with their current workflow.

### Be Factual
Make specific, verifiable claims. Avoid generalizations and euphemisms.

| Avoid | Prefer |
|-------|--------|
| "Credentials are kept secure" | "Credentials are resolved at the network layer and never stored in container environment variables" |
| "Full visibility into what happened" | "Canonical log lines record method, host, path, status, duration, and credential injection details per request" |
| "Enterprise-grade security" | (Describe the specific security properties) |

If you can't point to a specific mechanism, the claim is too vague.

### Be Direct
Write in active voice. State what things do, not what they "can" or "may" do.

| Avoid | Prefer |
|-------|--------|
| "You can use the `host` field to match requests" | "The `host` field matches requests" |
| "Gatekeeper may automatically detect the token prefix" | "Gatekeeper detects the token prefix automatically" |
| "It is possible to configure multiple credential sources" | "Configure multiple credential sources" |

### Be Concise
Eliminate filler words. Every sentence should convey information.

| Avoid | Prefer |
|-------|--------|
| "In order to start the proxy, you need to..." | "To start the proxy..." |
| "It's important to note that tokens are never..." | "Tokens are never..." |
| "Basically, what happens is that the proxy..." | "The proxy..." |

### Be Precise
Use specific terms consistently. Avoid synonyms that create ambiguity.

| Term | Definition | Don't use |
|------|------------|-----------|
| **credential source** | A backend that provides a credential value | provider, backend, fetcher |
| **grant** | A named label for a credential, used in logging and network policy | permission, access |
| **inject** | Add credentials at the network layer | pass, provide, supply |
| **intercept** | Terminate and re-establish TLS to read plaintext requests | decrypt, unwrap |

### Be Practical
Lead with what users need to do, not theory. Show working examples first, explain after.

```markdown
<!-- Avoid: Theory first -->
Gatekeeper uses a TLS-intercepting proxy to inject credentials. The proxy
terminates the client's TLS, reads the plaintext request, and adds
Authorization headers. To use this feature:

<!-- Prefer: Action first -->
Configure a credential source in gatekeeper.yaml:

    credentials:
      - host: api.github.com
        source:
          type: env
          var: GITHUB_TOKEN

The token is injected at the network layer—it never appears in the
client command.
```

### Be Honest About Limitations
Document what Gatekeeper doesn't do, edge cases, and known issues. Users trust documentation that acknowledges limitations.

```markdown
<!-- Good: Acknowledges limitation -->
> **Note:** Gatekeeper fetches the secret once at startup. To pick up
> a rotated secret, restart the proxy.

<!-- Good: States trade-off -->
Applications with certificate pinning will fail even with the CA
trusted. This is expected—interception requires replacing the origin
certificate.
```

## Formatting Conventions

### Headings
- Use sentence case: "Getting started" not "Getting Started"
- Keep headings short (under 6 words when possible)
- Don't skip levels (h2 → h4)

### Code Blocks
Always specify the language for syntax highlighting:

````markdown
```bash
gatekeeper --config gatekeeper.yaml
```

```yaml
credentials:
  - host: api.github.com
    source:
      type: env
      var: GITHUB_TOKEN
```

```go
ca, _ := proxy.LoadCA(certPEM, keyPEM)
```
````

Use `text` for log output and ASCII diagrams.

### Inline Code
Use backticks for:
- Commands: `gatekeeper`
- Flags: `--config`
- File names: `gatekeeper.yaml`
- Environment variables: `OTEL_EXPORTER_OTLP_ENDPOINT`
- Field names: `source.type`, `host`
- Values: `"strict"`, `"permissive"`
- Header names: `Authorization`

Don't use backticks for:
- Product names: Gatekeeper, Docker, GitHub
- General concepts: credential injection, TLS interception

### File Paths
- Use relative paths when referring to project files: `./gatekeeper.yaml`
- Use absolute paths only when necessary for system paths

### Lists
Use bullet lists for unordered items. Use numbered lists only for sequential steps.

### Tables
Use tables for structured comparisons and field definitions. Keep cells concise.

### Admonitions
Use blockquotes with bold labels for callouts:

```markdown
> **Note:** Additional context that's helpful but not critical.

> **Warning:** Something that could cause problems if ignored.
```

## Content Guidelines

### Show Real Output
When documenting commands, use realistic output that matches what users will see. Test commands before documenting them.

### Explain the "Why"
Don't just show what to do—briefly explain why it matters.

### Link to Related Content
Cross-reference related pages. Use relative links:

```markdown
See [Credential Sources](../concepts/03-credential-sources.md) for details
on how the refresh lifecycle works.
```

### Credential Safety
Never log or display real credential values. Use placeholders:
- `ghp_xxxx` for GitHub tokens
- `sk-xxxx` for API keys
- `Bearer ghp_xxxx` for Authorization headers
- `my-secret-token` for generic placeholders

### Error Messages
When documenting errors, show the full error message and explain how to resolve it.

## Section Definitions

The documentation has four sections. Each serves a distinct purpose.

### Getting Started

**Purpose:** Onboard new users from install to first successful proxy run.

**Audience:** Someone who has never used Gatekeeper.

**Contains:** Installation instructions, a guided walkthrough, and orientation material. Pages are sequential—each builds on the previous one.

**Does not contain:** Deep explanations, exhaustive configuration options, or advanced workflows.

### Concepts

**Purpose:** Explain *how things work* and *why they are designed that way*. Build mental models.

**Audience:** Someone who wants to understand the system, not accomplish a specific task.

**Contains:** Architecture, design decisions, trade-offs, data flow descriptions. Describes mechanisms and explains rationale.

**Does not contain:** Step-by-step instructions or exhaustive configuration tables. Link to guides for "how" and reference for "all options."

**Test:** If you removed all code blocks and the page still makes sense, it's a concept page.

### Guides

**Purpose:** Help users accomplish specific tasks. Answer "how do I do X?"

**Audience:** Someone who has a goal and needs steps to reach it.

**Contains:** Prerequisites, step-by-step instructions, working examples, verification steps. May include brief context (3-5 sentences) to orient the reader, but the bulk is procedural.

**Does not contain:** Deep architectural explanations or exhaustive option tables.

**Test:** The page should read as a recipe. A reader should be able to follow it start-to-finish and achieve a result.

### Reference

**Purpose:** Provide complete, structured specifications. Answer "what are all the options?"

**Audience:** Someone who knows what they want to do and needs exact syntax, fields, or values.

**Contains:** Configuration schemas with all fields, environment variable tables, format specifications. Every option documented with type, default, and description.

**Does not contain:** Extended explanations or guided workflows.

**Test:** The page should work as a lookup table. A reader should be able to find any option in under 10 seconds.

## Frontmatter Template

Every documentation page should start with this frontmatter:

```yaml
---
title: "Page Title"
description: "One sentence description for SEO and link previews."
keywords: ["gatekeeper", "relevant", "keywords"]
---
```

The following are inferred from the file path and don't need to be specified:
- `slug` — From filename (e.g., `01-introduction.md` → `introduction`)
- `section` — From parent directory
- `order` — From numeric prefix
- `prev`/`next` — From adjacent files

## Terminology

### Capitalize
- Gatekeeper (the product)
- Docker
- GitHub, GitLab
- macOS, Linux, Windows

### Don't Capitalize
- container, proxy
- credential, token, grant
- network policy
- audit log, trace

### Abbreviations
Spell out on first use, then use abbreviation:

- TLS (Transport Layer Security)
- CLI (command-line interface)
- API (application programming interface)
- CA (Certificate Authority)
- MCP (Model Context Protocol)
- STS (Security Token Service)
- OTel (OpenTelemetry)

Common abbreviations that don't need expansion:
- URL, HTTP, HTTPS
- JSON, YAML
- ID (identifier)
