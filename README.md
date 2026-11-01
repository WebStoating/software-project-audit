# software-project-audit

An [Agent Skill](https://agentskills.io/specification) that runs a risk-based, evidence-driven Standard Audit of the project in the agent's working directory. It covers Python and JavaScript/TypeScript/Node/frontend projects across 11 domains (architecture, code quality, security and privacy, dependencies, data, testing, CI/CD, infrastructure, observability, performance, documentation), with security mapped to OWASP Top 10:2025 and CWE Top 25. Scanners run in a pinned Docker image. Unit tests and coverage run on your machine, in the environment you prepared, only if you say up front that you trust the environment and want them run, and only after you confirm the exact commands. Say no, and no project code runs at all. The project is never modified. The skill works in Claude Code and in Codex.

The output goes to `<project>/audit/`: `AUDIT_REPORT.md`, `FINDINGS.json`, `AUDIT_COVERAGE.json`, `REMEDIATION_PLAN.md` and raw evidence in `audit/raw/`. It's a draft for the developer to review and edit.

## Prerequisites

- **Python 3.9 or newer** on the host. The skill's scripts use only the standard library.
- **Docker** with a running daemon. The scanner image (`assets/scanner.Dockerfile`, pinned by digest and checksums) builds locally on first use, which takes several minutes.
- **The project set up for local development** before you start the audit: dependencies installed (a venv or `node_modules`), `.env` and other local config in place, and any services the tests need running. The skill never installs the project's dependencies or invents settings. A package that isn't set up is skipped and reported.
- **Network access** for the image build, the scanners and temporary coverage-tool installs. Dependency advisory lookups send package names and versions, never source code. No tool uploads source. The code the agent reads is processed by the agent's model provider, and the report names the agent and provider.
- An agent that supports Agent Skills: Claude Code or Codex. If the agent runs in a sandbox, it must allow Docker and network access. The skill's readiness step tells you what to grant.

## Install

From the repository root:

```bash
./install.sh
```

This symlinks the skill folder `software-project-audit/` into both agents' user-level skill directories:

| Agent | Default skills directory | Override |
|---|---|---|
| Claude Code | `${CLAUDE_CONFIG_DIR:-$HOME/.claude}/skills/` | `--claude-dir DIR` |
| Codex | `$HOME/.agents/skills/` (the user-level location in the [OpenAI Codex skills docs](https://developers.openai.com/codex/skills), which also say Codex follows symlinked skill folders) | `--codex-dir DIR` |

The link is `DIR/software-project-audit`. Because it is a symlink, edits in this repository take effect immediately, and you don't need to reinstall.

- Re-running `./install.sh` is safe. An existing link to this skill is left as is.
- `--no-claude` or `--no-codex` installs for one agent only (they also limit `--uninstall`).
- If something else is already at a target path (a real directory or file, or a link to another folder), the script changes nothing, prints what it found and exits 1. Move it away yourself and rerun.
- `./install.sh --uninstall` removes the two links, but only if they point at this repository's skill folder. Anything else is left in place.

Prefer this user-level install to a project-level link (`<dir>/.claude/skills/`). Claude Code doesn't find a link in a parent folder's `.claude/skills/` when the session starts inside a nested git repository, and it then audits without the skill.

Restart the agent (or start a new session) after installing so it picks up the skill.

## Use

In the project you want to audit, ask the agent for an audit, for example "audit this project" or "run a security review against OWASP Top 10". The skill:

1. Checks readiness: Python, Docker and the sandbox's network and Docker permissions.
2. Asks you, in one message, about the audit goal, stage, critical workflows and data sensitivity, and whether you trust the project and its environment enough to run its unit tests.
3. Discovers the project and runs the scanners. If you agreed to the test run, it then shows you the exact test commands and runs them on your machine once you confirm; if you declined, testing is reviewed from source only. If a coverage tool is missing, it is installed temporarily, removed afterwards, and the report suggests adding it to the project.
4. Analyses workflows and domains, using parallel subagents when the agent supports them.
5. Validates findings and coverage, then renders the report.

Scans run without asking again. Project code runs only in the test step you confirmed, with agent, forge and cloud credential variables removed from its environment.

## Repository layout

| Path | Contents |
|---|---|
| `software-project-audit/` | The skill (the only part that ships): `SKILL.md`, `scripts/`, `references/`, `assets/` |
| `software-project-audit/references/methodology.md` | The audit methodology, the source of truth for audit content |
| `tests/` | pytest suite, fixture projects with planted issues, recorded tool output |
| `install.sh` | The installer described above |

## Editing the methodology

`software-project-audit/references/methodology.md` is the only methodology file; edit it in place. After you change it:

1. Run `uv run pytest`. `test_every_check_has_a_checklist_section` fails for every check ID that was added, renamed or removed. Update the matching section in `software-project-audit/references/checklist-*.md`.
2. If the change touches vocabularies, schemas, scanners or the report contract, update the code in `software-project-audit/scripts/auditlib/`, the schemas and templates in `software-project-audit/assets/` in the same change.

Check IDs are never hard-coded. The scripts parse them from the methodology at runtime.

## Running the tests

The tests need [uv](https://docs.astral.sh/uv/). Run them from the repository root:

```bash
uv run pytest                          # full suite; Docker tests skip when Docker isn't running
uv run pytest -m "not docker and not hostrun"  # fast suite: no Docker, no venv/node_modules builds
uv run pytest tests/test_install.py    # one file
```

To validate the skill package against the Agent Skills standard:

```bash
uvx --from "git+https://github.com/agentskills/agentskills#subdirectory=skills-ref" skills-ref validate software-project-audit
```

See `AGENTS.md` for contributor rules, including commit conventions and the hard rules for skill scripts.
