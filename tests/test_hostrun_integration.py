"""Real test runs on fixture copies: a real venv / node_modules, temporary coverage tools, full cleanup."""
import json
import shutil
import subprocess

import pytest

import audit
from auditlib.paths import AuditPaths
from helpers import make_fixture_repo, make_real_venv, tree_hash, write_context

pytestmark = pytest.mark.hostrun


@pytest.fixture(autouse=True)
def _no_active_venv(monkeypatch):
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)  # uv run exports this repo's own venv


def _preview_and_run(project):
    p = str(project)
    assert audit.main(["discover", "--project", p]) == 0
    write_context(project)
    assert audit.main(["test", "--project", p]) == 0
    assert audit.main(["test", "--project", p, "--run"]) == 0
    return json.loads((AuditPaths.for_project(project).raw / "test-results.json").read_text(encoding="utf-8"))


def test_py_fixture_host_run_with_temp_coverage(tmp_path):
    project = make_fixture_repo("py-app", tmp_path).resolve()
    venv = make_real_venv(project, "pytest==8.3.3")
    before = tree_hash(project, skip=("audit", ".venv"))
    venv_before = tree_hash(venv)
    (res,) = _preview_and_run(project)["results"]
    assert res["status"] == "completed", res
    assert res["coverage"] is not None and res["counts"]["failed"] == 1  # the planted DB test
    assert "pytest-cov" in res["coverage_tool_suggestion"]
    assert not list(venv.glob("lib/python*/site-packages/pytest_cov"))
    assert tree_hash(venv) == venv_before
    assert not (AuditPaths.for_project(project).raw / ".tools").exists()
    assert tree_hash(project, skip=("audit", ".venv")) == before


@pytest.mark.skipif(shutil.which("npm") is None, reason="npm not installed")
def test_ts_fixture_host_run_with_temp_vitest_provider(tmp_path):
    project = make_fixture_repo("ts-app", tmp_path).resolve()
    subprocess.run(["npm", "ci", "--no-audit", "--no-fund"], cwd=project, check=True, capture_output=True)
    manifests = {n: (project / n).read_bytes() for n in ("package.json", "package-lock.json")}
    (res,) = _preview_and_run(project)["results"]
    assert res["coverage"] is not None, res
    assert "@vitest/coverage-v8" in res["coverage_tool_suggestion"]
    provider = project / "node_modules" / "@vitest" / "coverage-v8"
    assert not provider.exists() and not provider.is_symlink()
    assert {n: (project / n).read_bytes() for n in manifests} == manifests
    assert not (AuditPaths.for_project(project).raw / ".tools").exists()


def test_py_fixture_not_set_up_is_skipped(tmp_path):
    project = make_fixture_repo("py-app", tmp_path).resolve()
    data = _preview_and_run(project)
    assert data["results"] == []
    assert data["skipped"][0]["reason"].startswith("project not set up locally")


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv not installed")
def test_py_fixture_uv_venv_without_pip_gets_coverage(tmp_path):
    project = make_fixture_repo("py-app", tmp_path).resolve()
    subprocess.run(["uv", "venv", "-q", str(project / ".venv")], check=True, capture_output=True)
    subprocess.run(["uv", "pip", "install", "-q", "--python", str(project / ".venv" / "bin" / "python"),
                    "pytest==8.3.3"], check=True, capture_output=True)
    (res,) = _preview_and_run(project)["results"]
    assert res["status"] == "completed" and res["coverage"] is not None, res
