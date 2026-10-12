# Copilot review instructions

Review each pull request against the architecture as a whole, not the diff alone.

- Read the installed `architecture-review` skill (`.agents/skills/architecture-review/SKILL.md`) first, then the gatekeeper checks in `.github/skills/gatekeeper-architecture-review/SKILL.md`, and answer their questions for every change.
- Apply the installed `go-guide` skill (`.agents/skills/go-guide/SKILL.md`) to every new or changed Go package, exported API, and test.
- Read the root `AGENTS.md` and the doc under `docs/` for the area a change touches. Cite it as `path:line` for each architecture finding.
- A credential value in a log, error, span, or temp file is a High-confidence finding. So is a path that skips proxy authentication or widens host matching.
- Do not flag pure style or formatting. Do not flag a violation that already existed and that the change does not touch.
