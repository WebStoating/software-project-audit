import os
import shutil
import subprocess
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"
# Tool names specific to one agent; SKILL.md and references/ must not contain them.
FORBIDDEN_TOOL_NAMES = ["AskUserQuestion", "TodoWrite", "Task tool", "Agent tool", "spawn_agent", "apply_patch"]
_DATE = "2026-01-01T00:00:00+00:00"


def make_fixture_repo(name: str, tmp_path: Path, git: bool = True) -> Path:
    """Copy tests/fixtures/<name> into tmp_path/<name>; optionally commit it deterministically."""
    dest = Path(tmp_path) / name
    shutil.copytree(FIXTURES / name, dest, ignore=shutil.ignore_patterns("node_modules", "__pycache__"))
    if git:
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(GIT_AUTHOR_DATE=_DATE, GIT_COMMITTER_DATE=_DATE,
                   GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
        base = ["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
                "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false"]
        subprocess.run(base + ["init", "-q", "-b", "main"], cwd=dest, env=env, check=True)
        subprocess.run(base + ["add", "-A"], cwd=dest, env=env, check=True)
        subprocess.run(base + ["commit", "-q", "-m", "fixture"], cwd=dest, env=env, check=True)
    return dest


VALID_AUDIT = Path(__file__).resolve().parent / "data" / "valid-audit"


def build_coverage() -> dict:
    """AUDIT_COVERAGE.json for the valid-audit baseline.

    Generated rather than hand-listed so the 150+ check IDs follow the running methodology document.
    Every check is reviewed_no_issue except SEC-03 (verified_fail, AUD-001) and TEST-08 (verified_pass).
    """
    from auditlib.methodology import load_check_ids
    from auditlib.models import DOMAINS
    from auditlib.standards import cwe_ids, owasp_ids

    special = {
        "SEC-03": {"outcome": "verified_fail", "evidence": ["AUD-001"]},
        "TEST-08": {"outcome": "verified_pass", "evidence": ["raw/test-results.json"]},
    }
    domains = []
    for n, (did, ids) in enumerate(load_check_ids().items()):
        domains.append({
            "id": did, "applicable": True, "maturity": "Not verified" if did == "D11" else 1 + n % 4,
            "rationale": DOMAINS[did], "confidence": "Strongly supported",
            "checks": [dict({"id": c, "outcome": "reviewed_no_issue", "evidence": ["src/app.py"]}, **special.get(c, {}))
                       for c in ids],
        })
    owasp = [{"id": i, "outcome": "reviewed_no_issue", "method": "manual review"} for i in owasp_ids()]
    for o in owasp:
        if o["id"] == "A05:2025":
            o.update(outcome="verified_fail", findings=["AUD-001"])
    cwe = [{"id": i, "outcome": "reviewed_no_issue", "method": "manual review"} for i in cwe_ids()]
    for c in cwe:
        if c["id"] == "CWE-89":
            c.update(outcome="verified_fail", findings=["AUD-001"])
    return {
        "scope": "src/", "domains": domains,
        "workflows": [{"name": "lookup", "entry_point": "src/app.py", "traced": True, "findings": ["AUD-001"]}],
        "standards": {"owasp": owasp, "cwe": cwe},
        "readiness": {"decision": "Ready with conditions", "goal": "pre-release review", "conditions": ["Fix AUD-001"]},
    }


def make_valid_audit(tmp_path: Path):
    """Copy the valid-audit baseline into tmp_path and write its generated coverage; returns AuditPaths."""
    import json
    from auditlib.paths import AuditPaths

    dest = Path(tmp_path) / "project"
    shutil.copytree(VALID_AUDIT / "project", dest)
    paths = AuditPaths.for_project(dest)
    (paths.audit / "AUDIT_COVERAGE.json").write_text(json.dumps(build_coverage(), indent=2) + "\n", encoding="utf-8")
    return paths


def write_context(project: Path, test_run_consent: bool = True) -> Path:
    """The context.json the agent writes after discover, with the developer's answer to the test-run question."""
    import json

    raw = Path(project) / "audit" / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    ctx = {"goal": "review", "agent": "test-agent", "model_provider": "test-provider",
           "test_run_consent": test_run_consent}
    (raw / "context.json").write_text(json.dumps(ctx) + "\n", encoding="utf-8")
    return raw / "context.json"


def make_stub_venv(d: Path, pytest_cov: bool = True) -> Path:
    """A virtual environment the planner accepts (pyvenv.cfg + executable bin/python); nothing runs it."""
    v = Path(d) / ".venv"
    (v / "bin").mkdir(parents=True)
    (v / "pyvenv.cfg").write_text("home = /usr/bin\n")
    exe = v / "bin" / "python"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    site = v / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    if pytest_cov:
        (site / "pytest_cov").mkdir()
    return v


def make_real_venv(project: Path, *packages: str) -> Path:
    """A working .venv in the project with the given packages installed (needs network)."""
    import sys

    v = Path(project) / ".venv"
    subprocess.run([sys.executable, "-m", "venv", str(v)], check=True, capture_output=True)
    if packages:
        subprocess.run([str(v / "bin" / "python"), "-m", "pip", "install", "-q", "--disable-pip-version-check",
                        *packages], check=True, capture_output=True)
    return v


def tree_hash(root: Path, skip=("audit",)) -> str:
    """Hash of every path and file under root, ignoring top-level entries named in skip and __pycache__."""
    import hashlib

    h = hashlib.sha256()
    for p in sorted(Path(root).rglob("*")):
        rel = p.relative_to(root)
        if rel.parts[0] in skip or "__pycache__" in rel.parts:
            continue
        h.update(str(rel).encode())
        if p.is_file() and not p.is_symlink():
            h.update(p.read_bytes())
    return h.hexdigest()
