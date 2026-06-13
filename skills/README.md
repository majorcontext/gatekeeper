# Gatekeeper skills

Agent [Skills](https://agentskills.io) for working with Gatekeeper. They follow
the open `SKILL.md` standard, so they work in Claude Code and other compatible
agents.

## Install

Using the [`skills`](https://github.com/vercel-labs/skills) CLI (no clone
needed):

```bash
# Install into the current project (symlinked, single source of truth)
npx skills add majorcontext/gatekeeper

# …or use it once without installing
npx skills use majorcontext/gatekeeper
```

Or copy `configuring-gatekeeper/` into your agent's skills directory (e.g.
`.claude/skills/`) manually.

## Available skills

| Skill                                                      | Use it to…                                                                 |
|-----------------------------------------------------------|----------------------------------------------------------------------------|
| [`configuring-gatekeeper`](configuring-gatekeeper/SKILL.md) | Write `gatekeeper.yaml`, generate the CA, choose a credential source, lock down egress, set up the Postgres/Neon data plane, and verify a working proxy. |

## Validating

The skills are checked against the open spec by a built-in linter, run in CI:

```bash
go run ./cmd/skill-lint
```

It enforces the [Agent Skills specification](https://agentskills.io/specification)
(frontmatter rules, name/dir match, description length, body size) and verifies
that every referenced `references/`, `scripts/`, and `assets/` file exists.
