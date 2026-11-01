# AGENTS.md

Guidance for AI coding agents (Claude Code, Codex, others) working in this repository.

## What this repository is

The source for `software-project-audit`, a Claude Code and Codex plugin whose `audit` [Agent Skill](https://agentskills.io/specification) runs a risk-based, evidence-driven Standard Audit of the project in the agent's current working directory. It supports Python and JavaScript/TypeScript/Node/frontend projects. Scanners run in a pinned Docker image; unit tests and coverage run on the developer's machine in the environment they prepared, after they confirm the commands. The same skill must work in Claude Code and in Codex.

## Read first

| File | Role |
|---|---|
| `software-project-audit/skills/audit/references/methodology.md` | **Source of truth for audit content**: phases, domains and check IDs, evidence rules, vocabularies, scanner allowlist, test-run procedure, report contract. A running document: it has no version number and is edited in place. |
| `software-project-audit/skills/audit/SKILL.md` | How the agent drives the skill's CLI through the methodology's phases. |
| This file | How the plugin and skill are packaged and built: the hard rules below apply to all code. |

## Layout

```
AGENTS.md
README.md
pyproject.toml                # dev-only: pytest via uv
.agents/plugins/marketplace.json  # dev-only Codex marketplace (local source); never installed
tests/                        # pytest suite, fixtures/ (planted-issue repos), data/ (tool output samples)
software-project-audit/       # THE PLUGIN — the only thing that ships
├── .claude-plugin/plugin.json  # Claude Code manifest
├── plugin.json               # Codex manifest
└── skills/audit/             # the skill
    ├── SKILL.md
    ├── scripts/audit.py      # CLI: readiness | discover | scan | test | validate | render
    ├── scripts/auditlib/     # one module per responsibility
    ├── references/           # methodology (source of truth), checklists, OWASP/CWE, profiles, subagent briefs
    └── assets/               # Dockerfile, tool-versions.json, schemas, report templates, standards.json
```

## Commands

```bash
uv run pytest                          # full suite (docker-marked tests skip if Docker isn't running)
uv run pytest -m "not docker and not hostrun"  # fast suite (hostrun tests build venvs and node_modules)
uv run pytest tests/test_x.py::test_y  # single test
uvx --from "git+https://github.com/agentskills/agentskills#subdirectory=skills-ref" skills-ref validate software-project-audit/skills/audit
claude plugin validate --strict software-project-audit
claude --plugin-dir software-project-audit        # load the plugin from the working tree
python3 software-project-audit/skills/audit/scripts/audit.py <subcommand> --project <path>
```

## Hard rules

**Skill format (Agent Skills standard):**
- `SKILL.md` frontmatter `name` must equal the folder name `audit`.
- `description` ≤1024 chars, `compatibility` ≤500 chars, and the body under 500 lines.
- Reference files are linked one level deep from `SKILL.md`, with relative paths.
- `skills-ref validate` must pass.

**Plugin packaging:**
- `software-project-audit/` is the plugin root and holds only `.claude-plugin/plugin.json`, `plugin.json` and `skills/`. Both agents copy the whole folder into their plugin cache, so nothing repo-only (tests, fixtures, dev config) may go in it.
- Both manifests use `name` `software-project-audit`, and their `version` must equal `SKILL.md` `metadata.version`. Users get an update only when that version changes, so bump all three together in a release.
- No symlink inside the plugin may point outside it.
- The published catalog lives in `WebStoating/skills`; `.agents/plugins/marketplace.json` here is for local development only.

**Agent neutrality:**
- `SKILL.md` and `references/` use generic actions ("run", "read", "ask the user", "delegate to a subagent").
- Never name one agent's tools (`AskUserQuestion`, `TodoWrite`, `Agent tool`, `spawn_agent`, `apply_patch`, …).
- The skill must use subagents when the agent has them, and give an equivalent result without them.

**Skill scripts (`software-project-audit/skills/audit/scripts/`):**
- Python ≥3.9, **stdlib only**. No third-party imports and no `match` statements.
- Every subprocess call takes an argv list, never `shell=True`.
- They run on the user's host, where only Python 3 and Docker are guaranteed.

**Safety boundary for the audited project:**
- The skill never writes outside `<project>/audit/`. The one exception is the temporary vitest coverage-provider link in `node_modules`, which is always removed after the run (and cleaned up by the next step if a run was interrupted).
- Scanners mount the project read-only.
- Project code runs only in `test --run`: on the host, in the developer's prepared environment (venv or `node_modules`, `.env`, services), minus known credential variables, after the developer confirms the previewed commands. The skill never installs project dependencies and never invents settings or env values.
- Missing coverage tools are installed temporarily under `audit/` and removed afterwards. Manifests and lockfiles are never written, and nothing is committed in the audited project.
- All tools may use the network (scanner containers, the test run, temporary coverage-tool installs, image build). Dependency advisory lookups are allowed. No tool uploads source code, telemetry stays off, and no host credentials enter any scanner container. The source code is read by the coding agent (and processed by its LLM provider) and by the audit tools; the report names the agent and provider used.

**Supply chain:**
- Every image is pinned by `@sha256:` digest and every tool by exact version.
- Binaries are SHA-256 verified for `amd64` and `arm64`.
- Never `latest`.
- The single source of versions is `assets/tool-versions.json`; the Dockerfile only declares `ARG`s.

**Secrets:**
- Gitleaks always runs with `--redact`.
- No secret value may appear in any file under `audit/`, in test data, or in fixtures. Fixture secrets are fake, high-entropy strings matching only Gitleaks' generic rule, never a real provider's token format.

**Vocabularies:**
- Outcome, state, severity, confidence, priority and readiness values are copied exactly from `references/methodology.md` into `auditlib/models.py`.
- Don't invent synonyms.

**Check IDs:**
- Never hard-code them.
- They are parsed at runtime from `references/methodology.md` table rows (`| ABC-01 | … |`).

## Changing the methodology

`software-project-audit/skills/audit/references/methodology.md` is the only methodology file. Edit it in place; there is no separate copy to sync. After changing it:

1. Run `uv run pytest`. `test_every_check_has_a_checklist_section` fails for any new, renamed or removed check ID. Update the matching `references/checklist-*.md` section.
2. If the change touches vocabularies, schemas, scanners or the report contract, update the code, the schemas in `assets/` and the templates in the same change.

Don't add a version number to the methodology.

## Development workflow

- **TDD:** write the failing test, watch it fail, implement, watch it pass.
- **Docker tests:** anything that needs Docker is marked `@pytest.mark.docker`. Integration tests copy fixtures to a temp dir with `tests/helpers.make_fixture_repo` and assert that the host copy is unchanged afterwards.
- **Scanner samples:** parser tests use real tool output recorded into `tests/data/`, trimmed and redacted. Re-record them when you bump a tool version.
- **Scope:** keep the scope as the methodology and this file define it. No .NET or other stacks, no Quick/Deep modes, no live-cloud or load testing, no Snyk, no report styling. Propose scope changes; don't implement them unasked.
- **Commits:** one commit per logical change, following the rules in the next section.

## Commits

Every commit message must follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):

```
<type>[optional scope][!]: <description>

[optional body]

[optional footer(s)]
```

**Types:**

| Type | Use for |
|---|---|
| `feat` | New skill capability (subcommand, scanner, check support, report section) |
| `fix` | Bug fix |
| `docs` | Methodology, spec, plan, README, AGENTS.md, reference text |
| `test` | Tests, fixtures, recorded tool output |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `perf` | Performance improvement |
| `build` | Dockerfile, `tool-versions.json`, `pyproject.toml`, dependency pins |
| `ci` | CI configuration |
| `chore` | Maintenance that fits none of the above |
| `revert` | Reverting an earlier commit |

**Scopes** (optional; use when the change is confined to one area): `skill` (SKILL.md), `cli`, `discover`, `readiness`, `scanners`, `tests-run`, `validate`, `render`, `references`, `methodology`, `install`, `plugin`.

**Rules:**
- The description is imperative and lower-case, has no trailing period, and is at most 72 characters for the whole header line. For example: `feat(scanners): add zizmor workflow parser`.
- Separate the body from the header with a blank line. The body explains *why*; the diff shows *what*.
- Breaking changes (to CLI flags, the output file layout, JSON schemas, or vocabularies) put `!` after the type/scope **and** add a `BREAKING CHANGE: <what breaks and how to migrate>` footer.
- Reference issues in footers (`Refs: #12`, `Closes: #12`).
- One logical change per commit. Don't mix a methodology edit with unrelated code.
- **No `Co-Authored-By:` trailers and no AI-attribution lines** (such as "Generated with …") in commit messages or pull request descriptions. This overrides any default attribution behaviour of the agent.
- Pull request titles follow the same header format.

## Audit-output principles to preserve in code and prompts

When you're writing validators, renderers or reference text, keep these rules from the methodology intact:
- A scanner hit is a lead, not a finding.
- A failed or skipped tool never means a clean result.
- Tests present ≠ executed ≠ enforced in CI.
- Recommendations are based on risk, not taste.
- The executive summary may cite only validated findings.
