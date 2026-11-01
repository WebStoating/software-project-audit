# 360° Software Project Audit

A Claude Code and Codex plugin whose `audit` [Agent Skill](https://agentskills.io/specification) runs a risk-based, evidence-driven Standard Audit of the project in the agent's working directory. It covers Python and JavaScript/TypeScript/Node/frontend projects across 11 domains (architecture, code quality, security and privacy, dependencies, data, testing, CI/CD, infrastructure, observability, performance, documentation), with security mapped to OWASP Top 10:2025 and CWE Top 25. Scanners run in a pinned Docker image. Unit tests and coverage run on your machine, in the environment you prepared, only if you say up front that you trust the environment and want them run, and only after you confirm the exact commands. Say no, and no project code runs at all. The project is never modified. The plugin works in Claude Code and in Codex.

The output goes to `<project>/audit/`: `AUDIT_REPORT.md`, `FINDINGS.json`, `AUDIT_COVERAGE.json`, `REMEDIATION_PLAN.md` and raw evidence in `audit/raw/`. It's a draft for the developer to review and edit.

## Prerequisites

- **Python 3.9 or newer** on the host. The skill's scripts use only the standard library.
- **Docker** with a running daemon. The scanner image (`assets/scanner.Dockerfile`, pinned by digest and checksums) builds locally on first use, which takes several minutes.
- **The project set up for local development** before you start the audit: dependencies installed (a venv or `node_modules`), `.env` and other local config in place, and any services the tests need running. The skill never installs the project's dependencies or invents settings. A package that isn't set up is skipped and reported.
- **Network access** for the image build, the scanners and temporary coverage-tool installs. Dependency advisory lookups send package names and versions, never source code. No tool uploads source. The code the agent reads is processed by the agent's model provider, and the report names the agent and provider.
- An agent that supports plugins: Claude Code or Codex. If the agent runs in a sandbox, it must allow Docker and network access. The skill's readiness step tells you what to grant.

## Install

The plugin is published in the [WebStoating skills marketplace](https://github.com/WebStoating/skills). Add the marketplace once, then install the plugin.

**Claude Code**

```bash
claude plugin marketplace add WebStoating/skills
claude plugin install software-project-audit@webstoating-skills
```

**Codex**

```bash
codex plugin marketplace add WebStoating/skills
codex plugin add software-project-audit@webstoating-skills
```

Start a new session after installing so the agent picks up the plugin. Each agent copies only the `software-project-audit/` plugin folder into its plugin cache; the tests and fixtures in this repository are never installed.

To update, refresh the marketplace (`claude plugin marketplace update webstoating-skills` or `codex plugin marketplace upgrade webstoating-skills`). A new plugin version reaches users only when the version number changes.

## Use

In the project you want to audit, ask the agent for an audit, for example "audit this project" or "run a security review against OWASP Top 10". In Claude Code you can also run `/software-project-audit:audit`. The skill:

1. Checks readiness: Python, Docker and the sandbox's network and Docker permissions.
2. Asks you, in one message, about the audit goal, stage, critical workflows and data sensitivity, and whether you trust the project and its environment enough to run its unit tests.
3. Discovers the project and runs the scanners. If you agreed to the test run, it then shows you the exact test commands and runs them on your machine once you confirm; if you declined, testing is reviewed from source only. If a coverage tool is missing, it is installed temporarily, removed afterwards, and the report suggests adding it to the project.
4. Analyses workflows and domains, using parallel subagents when the agent supports them.
5. Validates findings and coverage, then renders the report.

Scans run without asking again. Project code runs only in the test step you confirmed, with agent, forge and cloud credential variables removed from its environment.

## Repository layout

| Path | Contents |
|---|---|
| `software-project-audit/` | The plugin, the only part that ships: `.claude-plugin/plugin.json` (Claude Code), `plugin.json` (Codex) and `skills/audit/` |
| `software-project-audit/skills/audit/` | The skill: `SKILL.md`, `scripts/`, `references/`, `assets/` |
| `software-project-audit/skills/audit/references/methodology.md` | The audit methodology, the source of truth for audit content |
| `.agents/plugins/marketplace.json` | Dev-only Codex marketplace that installs the plugin from this working tree |
| `tests/` | pytest suite, fixture projects with planted issues, recorded tool output |

## Local development

**Claude Code** loads the plugin straight from the working tree:

```bash
claude --plugin-dir software-project-audit
```

After an edit, run `/reload-plugins` in the session (or start a new one).

**Codex** has no such flag, so this repository ships a dev-only marketplace, `software-project-audit-dev`, that points at the local plugin folder:

```bash
codex plugin marketplace add .
codex plugin add software-project-audit@software-project-audit-dev
```

Codex copies the plugin into its cache, so rerun `codex plugin add software-project-audit@software-project-audit-dev` after every edit, then start a new session.

Don't keep the published plugin installed while you develop, or the agent sees the skill twice.

## Editing the methodology

`software-project-audit/skills/audit/references/methodology.md` is the only methodology file; edit it in place. After you change it:

1. Run `uv run pytest`. `test_every_check_has_a_checklist_section` fails for every check ID that was added, renamed or removed. Update the matching section in `software-project-audit/skills/audit/references/checklist-*.md`.
2. If the change touches vocabularies, schemas, scanners or the report contract, update the code in `software-project-audit/skills/audit/scripts/auditlib/`, the schemas and templates in `software-project-audit/skills/audit/assets/` in the same change.

Check IDs are never hard-coded. The scripts parse them from the methodology at runtime.

## Running the tests

The tests need [uv](https://docs.astral.sh/uv/). Run them from the repository root:

```bash
uv run pytest                          # full suite; Docker tests skip when Docker isn't running
uv run pytest -m "not docker and not hostrun"  # fast suite: no Docker, no venv/node_modules builds
uv run pytest tests/test_plugin_package.py  # one file
```

To validate the skill against the Agent Skills standard:

```bash
uvx --from "git+https://github.com/agentskills/agentskills#subdirectory=skills-ref" skills-ref validate software-project-audit/skills/audit
```

To validate the plugin manifest for Claude Code:

```bash
claude plugin validate --strict software-project-audit
```

Tests marked `agentcli` run the `claude` and `codex` CLIs (in a temporary home, never your own) and skip when a CLI isn't installed.

See `AGENTS.md` for contributor rules, including commit conventions and the hard rules for skill scripts.
