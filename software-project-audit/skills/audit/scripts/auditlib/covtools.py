"""Temporary coverage tools: installed only for a test run, recorded first, always removed afterwards."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from .hostenv import build_env
from .paths import AuditPaths

STATE_NAME = "temp-tools.json"
_SUGGEST = {
    "uv": "`uv add --dev {tool}`",
    "poetry": "`poetry add --group dev {tool}`",
    "pipenv": "`pipenv install --dev {tool}`",
    "pip": "add `{tool}` to your dev requirements file",
    "npm": "`npm install -D {tool}@{version}`",
    "pnpm": "`pnpm add -D {tool}@{version}`",
    "yarn": "`yarn add -D {tool}@{version}`",
}


def _read_state(state: Path) -> list:
    try:
        return json.loads(state.read_text(encoding="utf-8"))["tools"]
    except (OSError, ValueError, KeyError, TypeError):
        return []


def _write_state(state: Path, tools: list) -> None:
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps({"tools": tools}, indent=2) + "\n", encoding="utf-8")


def _log(paths: AuditPaths, tool: dict, r) -> None:
    log = paths.raw / "tests" / Path(tool["target"]).name / "coverage_tools.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(str(log), "a", encoding="utf-8") as fh:
        fh.write("$ %s\n--- stdout ---\n%s\n--- stderr ---\n%s\n" % (" ".join(r.args), r.stdout, r.stderr))


def install(plan, paths: AuditPaths, base_env, timeout: int = 600) -> list:
    """Install the plan's temporary coverage tools. Returns notes; a failure costs coverage, not the run."""
    notes = []
    state = paths.raw / STATE_NAME
    env, _ = build_env(base_env, [], {})
    for tool in plan.temp_tools:
        tool = dict(tool, created_dirs=[])
        _write_state(state, _read_state(state) + [tool])  # record before touching anything
        pins = ["%s==%s" % kv for kv in tool["packages"].items()]
        if tool["kind"] == "python-target":
            argv = [plan.argv[0], "-m", "pip", "install", "--disable-pip-version-check", "--no-input",
                    "--no-deps", "--target", tool["target"]] + pins
        else:
            argv = ["npm", "install", "--prefix", tool["target"], "--no-audit", "--no-fund", "--ignore-scripts"]
            argv += ["%s@%s" % kv for kv in tool["packages"].items()]
        r = _install_run(argv, env, timeout, paths, tool)
        uv = shutil.which("uv", path=env.get("PATH"))
        if r.returncode != 0 and "No module named pip" in (r.stderr or "") and uv:
            # uv-created venvs ship without pip; uv installs into the same target for that interpreter
            r = _install_run([uv, "pip", "install", "--no-deps", "--target", tool["target"],
                              "--python", plan.argv[0]] + pins, env, timeout, paths, tool)
        if r.returncode != 0:
            notes.append("coverage not measured: no pip in venv" if "No module named pip" in (r.stderr or "")
                         else "coverage not measured: coverage tool install failed")
            continue
        if tool["link"]:
            notes += _link(tool, state)
    return notes


def _install_run(argv: list, env: dict, timeout: int, paths: AuditPaths, tool: dict):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        r = subprocess.CompletedProcess(argv, 1, "", "could not start installer")
    _log(paths, tool, r)
    return r


def _link(tool: dict, state: Path) -> list:
    link = Path(tool["link"])
    if os.path.lexists(str(link)):
        return ["coverage provider already present at %s; not replaced" % link.name]
    created, d = [], link.parent
    while not d.exists():
        created.append(str(d))
        d = d.parent
    tool["created_dirs"] = sorted(created, key=len)
    _write_state(state, [t if t["target"] != tool["target"] else tool for t in _read_state(state)])
    link.parent.mkdir(parents=True, exist_ok=True)
    name = Path(*Path(tool["link"]).parts[-2:])  # @vitest/coverage-v8
    os.symlink(str(Path(tool["target"]) / "node_modules" / name), str(link))
    return []


def _undo(tool: dict, audit_dir: Path) -> "tuple[bool, list]":
    """Remove one tool's link. Returns (removed a link, warnings)."""
    if not tool.get("link"):
        return False, []
    link = Path(tool["link"])
    if not os.path.lexists(str(link)):
        removed = False
    elif not link.is_symlink():
        return False, ["WARNING: %s is not our temporary link; left in place" % link]
    else:
        target = os.path.realpath(os.path.join(str(link.parent), os.readlink(str(link))))
        if not target.startswith(os.path.realpath(str(audit_dir)) + os.sep):
            return False, ["WARNING: %s points outside audit/; left in place" % link]
        os.unlink(str(link))
        removed = True
    for d in sorted(tool.get("created_dirs") or [], key=len, reverse=True):
        try:
            os.rmdir(d)
        except OSError:
            pass
    return removed, []


def _clear(state: Path, audit_dir: Path) -> "tuple[list, list]":
    removed, warnings = [], []
    for tool in _read_state(state):
        did, warn = _undo(tool, audit_dir)
        if did:
            removed.append(tool["link"])
        warnings += warn
    shutil.rmtree(str(state.parent / ".tools"), ignore_errors=True)
    try:
        state.unlink()
    except OSError:
        pass
    return removed, warnings


def remove(paths: AuditPaths) -> list:
    """Remove every recorded temporary tool of this run. Returns WARNING lines for anything left behind."""
    state = paths.raw / STATE_NAME
    if not state.exists() and not (paths.raw / ".tools").exists():
        return []
    return _clear(state, paths.audit.resolve())[1]


def cleanup_leftovers(project: Path) -> list:
    """Remove tools an interrupted run left behind, including runs already rotated into audit/history/."""
    paths = AuditPaths.for_project(project)
    states = [paths.raw / STATE_NAME] + sorted(paths.audit.glob("history/*/raw/" + STATE_NAME))
    lines = []
    for state in states:
        if not state.exists():
            continue
        removed, warnings = _clear(state, paths.audit.resolve())
        lines += ["WARNING: removed leftover temporary coverage tool %s" % r for r in removed] + warnings
    return lines


def suggestion(manager: str, tool: str, version: str) -> str:
    cmd = _SUGGEST.get(manager, "add `{tool}` to your dev dependencies").format(tool=tool, version=version)
    return "Add %s to your dev dependencies so coverage can be measured locally and in CI: %s" % (tool, cmd)
