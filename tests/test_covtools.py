import json
import subprocess
from pathlib import Path

from helpers import SKILL_DIR

from auditlib import covtools
from auditlib.paths import AuditPaths
from auditlib.testplan import TestPlan

VERSIONS = json.loads((SKILL_DIR
                       / "assets" / "tool-versions.json").read_text(encoding="utf-8"))
PINS = VERSIONS["coverage_tools"]


def _paths(tmp_path):
    p = AuditPaths.for_project(tmp_path)
    p.raw.mkdir(parents=True)
    return p


def _py_plan(paths):
    target = paths.raw / ".tools" / "python" / "root"
    return TestPlan(".", "python", "pip", "pytest", str(paths.project), argv=["/v/bin/python", "-m", "pytest"],
                    temp_tools=[{"kind": "python-target", "target": str(target), "link": None,
                                 "packages": {"pytest-cov": PINS["pytest-cov"], "coverage": PINS["coverage"]}}])


def _node_plan(paths, link):
    target = paths.raw / ".tools" / "node" / "root"
    return TestPlan(".", "javascript", "npm", "vitest", str(paths.project), argv=["vitest", "run"],
                    temp_tools=[{"kind": "vitest-provider", "target": str(target), "link": str(link),
                                 "packages": {"@vitest/coverage-v8": "2.1.9"}}])


def _state(paths):
    return json.loads((paths.raw / covtools.STATE_NAME).read_text())["tools"]


def test_install_python_records_state_before_running_pip(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    plan = _py_plan(paths)
    calls = []

    def fake_run(argv, **kw):
        assert _state(paths)[0]["target"] == plan.temp_tools[0]["target"]
        assert "GH_TOKEN" not in kw["env"]
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(covtools.subprocess, "run", fake_run)
    notes = covtools.install(plan, paths, {"GH_TOKEN": "x", "PATH": "/usr/bin"})
    assert notes == []
    assert calls == [["/v/bin/python", "-m", "pip", "install", "--disable-pip-version-check", "--no-input",
                      "--no-deps", "--target", plan.temp_tools[0]["target"],
                      "pytest-cov==" + PINS["pytest-cov"], "coverage==" + PINS["coverage"]]]


def test_install_python_without_pip_notes_and_skips(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    monkeypatch.setattr(covtools.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(
        argv, 1, "", "/v/bin/python: No module named pip"))
    assert covtools.install(_py_plan(paths), paths, {}) == ["coverage not measured: no pip in venv"]


def test_install_failure_is_noted(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    monkeypatch.setattr(covtools.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(
        argv, 1, "", "network down"))
    assert covtools.install(_py_plan(paths), paths, {}) == ["coverage not measured: coverage tool install failed"]


def test_install_vitest_provider_links_into_node_modules(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    nm = tmp_path / "node_modules"
    nm.mkdir()
    link = nm / "@vitest" / "coverage-v8"
    plan = _node_plan(paths, link)
    target = Path(plan.temp_tools[0]["target"])
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        (target / "node_modules" / "@vitest" / "coverage-v8").mkdir(parents=True)
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(covtools.subprocess, "run", fake_run)
    assert covtools.install(plan, paths, {}) == []
    assert calls == [["npm", "install", "--prefix", str(target), "--no-audit", "--no-fund", "--ignore-scripts",
                      "@vitest/coverage-v8@2.1.9"]]
    assert link.is_symlink() and link.resolve() == (target / "node_modules" / "@vitest" / "coverage-v8").resolve()
    assert _state(paths)[0]["created_dirs"] == [str(nm / "@vitest")]


def test_install_never_replaces_existing_provider(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    link = tmp_path / "node_modules" / "@vitest" / "coverage-v8"
    link.mkdir(parents=True)
    monkeypatch.setattr(covtools.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 0, "", ""))
    covtools.install(_node_plan(paths, link), paths, {})
    assert link.is_dir() and not link.is_symlink()


def _linked(tmp_path, paths):
    target = paths.raw / ".tools" / "node" / "root" / "node_modules" / "@vitest" / "coverage-v8"
    target.mkdir(parents=True)
    link = tmp_path / "node_modules" / "@vitest" / "coverage-v8"
    link.parent.mkdir(parents=True)
    link.symlink_to(target)
    return link


def _write_state(raw: Path, link, created=()):
    raw.mkdir(parents=True, exist_ok=True)
    (raw / covtools.STATE_NAME).write_text(json.dumps({"tools": [
        {"kind": "vitest-provider", "target": str(raw / ".tools" / "node" / "root"), "link": str(link),
         "packages": {"@vitest/coverage-v8": "2.1.9"}, "created_dirs": [str(c) for c in created]}]}))


def test_remove_unlinks_symlink_into_tools_and_deletes_tools_dir(tmp_path):
    paths = _paths(tmp_path)
    link = _linked(tmp_path, paths)
    _write_state(paths.raw, link, created=[link.parent])
    assert covtools.remove(paths) == []
    assert not link.exists() and not link.is_symlink() and not link.parent.exists()
    assert (tmp_path / "node_modules").is_dir()
    assert not (paths.raw / ".tools").exists() and not (paths.raw / covtools.STATE_NAME).exists()


def test_remove_refuses_symlink_pointing_elsewhere(tmp_path):
    paths = _paths(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    link = tmp_path / "node_modules" / "@vitest" / "coverage-v8"
    link.parent.mkdir(parents=True)
    link.symlink_to(elsewhere)
    _write_state(paths.raw, link)
    warnings = covtools.remove(paths)
    assert link.is_symlink()
    assert len(warnings) == 1 and warnings[0].startswith("WARNING")


def test_remove_leaves_real_directory_untouched(tmp_path):
    paths = _paths(tmp_path)
    link = tmp_path / "node_modules" / "@vitest" / "coverage-v8"
    link.mkdir(parents=True)
    _write_state(paths.raw, link)
    warnings = covtools.remove(paths)
    assert link.is_dir() and len(warnings) == 1 and warnings[0].startswith("WARNING")


def test_remove_without_state_is_noop(tmp_path):
    assert covtools.remove(_paths(tmp_path)) == []


def test_cleanup_leftovers_reads_history(tmp_path):
    paths = _paths(tmp_path)
    link = _linked(tmp_path, paths)
    old_raw = paths.audit / "history" / "20261027T000000Z" / "raw"
    _write_state(old_raw, link)
    lines = covtools.cleanup_leftovers(tmp_path)
    assert not link.is_symlink()
    assert lines == ["WARNING: removed leftover temporary coverage tool %s" % link]
    assert not (old_raw / covtools.STATE_NAME).exists()


def test_cleanup_leftovers_current_raw(tmp_path):
    paths = _paths(tmp_path)
    link = _linked(tmp_path, paths)
    _write_state(paths.raw, link)
    assert len(covtools.cleanup_leftovers(tmp_path)) == 1 and not link.is_symlink()
    assert covtools.cleanup_leftovers(tmp_path) == []


def test_suggestion_text_per_manager():
    assert covtools.suggestion("uv", "pytest-cov", "7.1.0") == (
        "Add pytest-cov to your dev dependencies so coverage can be measured locally and in CI: "
        "`uv add --dev pytest-cov`")
    assert covtools.suggestion("pip", "pytest-cov", "7.1.0") == (
        "Add pytest-cov to your dev dependencies so coverage can be measured locally and in CI: "
        "add `pytest-cov` to your dev requirements file")
    assert covtools.suggestion("pnpm", "@vitest/coverage-v8", "2.1.9") == (
        "Add @vitest/coverage-v8 to your dev dependencies so coverage can be measured locally and in CI: "
        "`pnpm add -D @vitest/coverage-v8@2.1.9`")


def test_install_python_without_pip_falls_back_to_uv(tmp_path, monkeypatch):
    paths = _paths(tmp_path)
    plan = _py_plan(paths)
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        if argv[1:3] == ["-m", "pip"]:
            return subprocess.CompletedProcess(argv, 1, "", "/v/bin/python: No module named pip")
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(covtools.subprocess, "run", fake_run)
    monkeypatch.setattr(covtools.shutil, "which", lambda name, path=None: "/usr/bin/uv" if name == "uv" else None)
    assert covtools.install(plan, paths, {"PATH": "/usr/bin"}) == []
    assert calls[1] == ["/usr/bin/uv", "pip", "install", "--no-deps", "--target", plan.temp_tools[0]["target"],
                        "--python", "/v/bin/python", "pytest-cov==" + PINS["pytest-cov"], "coverage==" + PINS["coverage"]]
