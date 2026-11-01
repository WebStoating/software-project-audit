import json

import pytest

import audit
from auditlib import dockerutil, testrun
from auditlib.ledger import load_runs
from auditlib.paths import AuditPaths
from helpers import make_fixture_repo, make_stub_venv, write_context


@pytest.fixture(autouse=True)
def _no_active_venv(monkeypatch):
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)  # uv run exports this repo's own venv


def _fake_result(plan, paths, base_env, **kw):
    return testrun.TestResult(plan.package_path, "completed", None, {"setup": 0, "test": 1},
                              {"passed": 2, "failed": 1, "skipped": 0, "errors": 0},
                              {"line_pct": 50.0, "branch_pct": None, "files": 1}, "audit/raw/tests/root", ["n"],
                              "Python 3.12.4", ["GH_TOKEN"], None)


def _project(tmp_path, pytest_cov=True):
    project = make_fixture_repo("py-app", tmp_path).resolve()
    make_stub_venv(project, pytest_cov=pytest_cov)
    assert audit.main(["discover", "--project", str(project)]) == 0
    write_context(project)
    return project


def _forbid_run(monkeypatch):
    def never(*a, **k):
        raise AssertionError("tests must not run without --run")
    monkeypatch.setattr(testrun, "run_test_plan", never)


def test_preview_writes_plan_and_runs_nothing(tmp_path, monkeypatch, capsys):
    project = _project(tmp_path, pytest_cov=False)
    monkeypatch.setenv("GH_TOKEN", "fake")
    _forbid_run(monkeypatch)
    capsys.readouterr()
    assert audit.main(["test", "--project", str(project)]) == 0
    out = capsys.readouterr().out
    saved = json.loads((AuditPaths.for_project(project).raw / "test-plan.json").read_text())
    assert set(saved) == {"digest", "plans", "skipped", "stripped_env"} and len(saved["digest"]) == 64
    assert str(project) not in json.dumps(saved)
    assert "GH_TOKEN" in saved["stripped_env"] and "GH_TOKEN" in out
    assert "cwd: <project>" in out
    assert "<project>/.venv/bin/python -m pytest" in out
    assert "pytest-cov==7.1.0" in out and "coverage==7.10.7" in out
    assert "--run" in out
    assert not (AuditPaths.for_project(project).raw / "test-results.json").exists()


@pytest.mark.parametrize("consent", [False, None, "yes"])
def test_refuses_without_consent_and_runs_nothing(tmp_path, monkeypatch, capsys, consent):
    project = _project(tmp_path)
    ctx = AuditPaths.for_project(project).raw / "context.json"
    if consent is None:
        ctx.unlink()
    else:
        ctx.write_text(json.dumps({"goal": "g", "test_run_consent": consent}), encoding="utf-8")
    _forbid_run(monkeypatch)
    for extra in ([], ["--run"]):
        assert audit.main(["test", "--project", str(project)] + extra) == 2
        assert "test_run_consent" in capsys.readouterr().err
    raw = AuditPaths.for_project(project).raw
    assert not (raw / "test-plan.json").exists() and not (raw / "test-results.json").exists()


def test_run_without_preview_refuses(tmp_path, monkeypatch, capsys):
    project = _project(tmp_path)
    _forbid_run(monkeypatch)
    assert audit.main(["test", "--project", str(project), "--run"]) == 2
    assert "without --run" in capsys.readouterr().err


def test_run_with_changed_plan_refuses(tmp_path, monkeypatch, capsys):
    project = _project(tmp_path)
    _forbid_run(monkeypatch)
    assert audit.main(["test", "--project", str(project)]) == 0
    assert audit.main(["test", "--project", str(project), "--run", "--command", ".=pytest -q"]) == 2
    assert "plan changed" in capsys.readouterr().err


def test_run_executes_and_writes_results_and_ledger(tmp_path, monkeypatch, capsys):
    project = _project(tmp_path)
    seen = {}

    def fake(plan, paths, base_env, **kw):
        seen["plan"] = plan
        return _fake_result(plan, paths, base_env)
    monkeypatch.setattr(testrun, "run_test_plan", fake)
    assert audit.main(["test", "--project", str(project), "--command", ".=pytest -x"]) == 0
    assert audit.main(["test", "--project", str(project), "--run", "--command", ".=pytest -x"]) == 0
    assert seen["plan"].argv == ["pytest", "-x"]
    raw = AuditPaths.for_project(project).raw
    data = json.loads((raw / "test-results.json").read_text())
    assert set(data) == {"plans", "skipped", "results"} and data["results"][0]["status"] == "completed"
    assert data["results"][0]["runtime_version"] == "Python 3.12.4"
    assert str(project) not in json.dumps(data)
    (rec,) = load_runs(raw)
    assert rec.tool == "tests:." and rec.status == "completed" and rec.counts["passed"] == 2
    assert rec.version == "Python 3.12.4" and rec.argv == ["pytest", "-x"]
    assert "Python 3.12.4" in capsys.readouterr().out


def test_env_assignment_override_exits_2(tmp_path, monkeypatch, capsys):
    project = _project(tmp_path)
    _forbid_run(monkeypatch)
    assert audit.main(["test", "--project", str(project), "--command", ".=DB_HOST=x pytest"]) == 2
    assert "settings must come from the developer's setup" in capsys.readouterr().err


def test_rejects_bad_override(tmp_path, monkeypatch):
    project = _project(tmp_path)
    _forbid_run(monkeypatch)
    assert audit.main(["test", "--project", str(project), "--command", "no-equals"]) == 2
    assert audit.main(["test", "--project", str(project), "--command", "nope=pytest"]) == 2


def test_python_flag_validates_package_path(tmp_path, monkeypatch, capsys):
    project = _project(tmp_path)
    _forbid_run(monkeypatch)
    assert audit.main(["test", "--project", str(project), "--python", "nope=/usr/bin/python3"]) == 2
    assert audit.main(["test", "--project", str(project), "--python", "no-equals"]) == 2
    assert audit.main(["test", "--project", str(project), "--python",
                       ".=%s" % (project / ".venv" / "bin" / "python")]) == 0


def test_no_docker_needed(tmp_path, monkeypatch):
    project = _project(tmp_path)
    _forbid_run(monkeypatch)
    monkeypatch.setattr(dockerutil, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("docker used")))
    assert audit.main(["test", "--project", str(project)]) == 0


def test_reruns_and_keeps_scanner_records(tmp_path, monkeypatch, capsys):
    from auditlib.ledger import append_run
    from auditlib.models import RunRecord

    project = _project(tmp_path)
    raw = AuditPaths.for_project(project).raw
    append_run(raw, RunRecord("semgrep", "1.0", ["semgrep"], "2026-01-01T00:00:00Z", 1.0, 0, "completed",
                              "scanners/semgrep.json", None, {"leads": 0}))
    seen = []

    def fake(plan, paths, base_env, **kw):
        seen.append(sorted(p.name for p in (paths.raw / "tests").glob("*")) if (paths.raw / "tests").exists() else [])
        return _fake_result(plan, paths, base_env)
    monkeypatch.setattr(testrun, "run_test_plan", fake)
    for _ in range(2):
        assert audit.main(["test", "--project", str(project)]) == 0
        assert audit.main(["test", "--project", str(project), "--run"]) == 0
        (raw / "tests" / "root").mkdir(parents=True, exist_ok=True)  # what a run leaves behind
    assert seen == [[], []]
    assert sorted(r.tool for r in load_runs(raw)) == ["semgrep", "tests:."]


def test_run_cleans_leftovers_first(tmp_path, monkeypatch, capsys):
    project = make_fixture_repo("ts-app", tmp_path).resolve()
    audit.main(["discover", "--project", str(project)])
    link = _leftover(project)
    _forbid_run(monkeypatch)
    capsys.readouterr()
    audit.main(["test", "--project", str(project)])
    assert not link.is_symlink()
    assert "WARNING: removed leftover temporary coverage tool" in capsys.readouterr().out

def _leftover(project):
    from auditlib import covtools
    raw = AuditPaths.for_project(project).raw
    target = raw / ".tools" / "node" / "root" / "node_modules" / "@vitest" / "coverage-v8"
    target.mkdir(parents=True)
    link = project / "node_modules" / "@vitest" / "coverage-v8"
    link.parent.mkdir(parents=True)
    link.symlink_to(target)
    (raw / covtools.STATE_NAME).write_text(json.dumps({"tools": [
        {"kind": "vitest-provider", "target": str(raw / ".tools" / "node" / "root"), "link": str(link),
         "packages": {"@vitest/coverage-v8": "2.1.9"}, "created_dirs": []}]}))
    return link


def test_discover_cleans_leftover_tools_before_rotation(tmp_path, capsys):
    project = make_fixture_repo("ts-app", tmp_path).resolve()
    link = _leftover(project)
    assert audit.main(["discover", "--project", str(project)]) == 0
    assert not link.is_symlink()
    assert "WARNING: removed leftover temporary coverage tool %s" % link in capsys.readouterr().out


def test_render_cleans_leftover_tools(tmp_path, capsys):
    project = make_fixture_repo("ts-app", tmp_path).resolve()
    link = _leftover(project)
    audit.main(["render", "--project", str(project)])
    assert not link.is_symlink()
    assert "WARNING: removed leftover temporary coverage tool %s" % link in capsys.readouterr().out


def test_sigterm_during_run_stops_tests_and_cleans_up(tmp_path):
    import os
    import signal
    import subprocess
    import sys
    import time
    from pathlib import Path

    project = _project(tmp_path)
    script = Path(audit.__file__)
    env = {k: v for k, v in os.environ.items() if k != "VIRTUAL_ENV"}
    base = [sys.executable, str(script), "test", "--project", str(project), "--command", ".=sleep 4711"]
    subprocess.run(base, env=env, check=True, capture_output=True)
    proc = subprocess.Popen(base + ["--run"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log = AuditPaths.for_project(project).raw / "tests" / "root" / "test.log"
    deadline = time.time() + 15
    while not log.exists() and time.time() < deadline:
        time.sleep(0.1)
    time.sleep(0.5)
    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=15)

    def alive():
        return subprocess.run(["pgrep", "-f", "sleep 4711"], capture_output=True).returncode == 0
    deadline = time.time() + 5
    while alive() and time.time() < deadline:
        time.sleep(0.1)
    if alive():
        subprocess.run(["pkill", "-f", "sleep 4711"])
        pytest.fail("test process survived SIGTERM to audit.py")
    assert proc.returncode == 2
    assert "interrupted" in proc.stderr.read().decode()


def test_result_notes_are_redacted_in_results_and_ledger(tmp_path, monkeypatch):
    project = _project(tmp_path)

    def fake(plan, paths, base_env, **kw):
        res = _fake_result(plan, paths, base_env)
        res.notes = ["WARNING: %s/node_modules/@vitest/coverage-v8 is not our temporary link; left in place" % project]
        return res
    monkeypatch.setattr(testrun, "run_test_plan", fake)
    assert audit.main(["test", "--project", str(project)]) == 0
    assert audit.main(["test", "--project", str(project), "--run"]) == 0
    raw = AuditPaths.for_project(project).raw
    text = (raw / "test-results.json").read_text() + (raw / "run-ledger.json").read_text()
    assert str(project) not in text and "<project>/node_modules/@vitest/coverage-v8" in text
