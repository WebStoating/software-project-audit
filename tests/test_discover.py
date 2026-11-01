import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from auditlib import discover
from helpers import make_fixture_repo

AUDIT_PY = Path(__file__).resolve().parent.parent / "software-project-audit" / "scripts" / "audit.py"


def test_discover_python_fixture(tmp_path):
    repo = make_fixture_repo("py-app", tmp_path)
    inv = discover.discover(repo)
    assert inv["stacks"] == ["python"]
    assert len(inv["packages"]) == 1
    pkg = inv["packages"][0]
    assert pkg["manager"] == "pip"
    assert pkg["runtime_version"] == "3.12"
    assert pkg["runtime_version_source"] == ".python-version"
    assert pkg["test_runner"] == "pytest"
    assert pkg["has_tests"] is True
    assert inv["github_workflows"] is True
    assert inv["ci_files"] == [".github/workflows/ci.yml"]
    assert inv["dockerfiles"] == ["Dockerfile"]
    assert inv["git"]["is_repo"] and inv["git"]["has_commits"] and not inv["git"]["dirty"]
    assert set(inv) == {
        "project", "git", "stacks", "packages", "ci_files", "github_workflows", "dockerfiles",
        "compose_files", "iac_files", "k8s_files", "env_templates", "migrations_dirs", "docs",
        "ai_sdks", "unsupported_stacks", "file_counts"}


def test_discover_ts_fixture(tmp_path):
    repo = make_fixture_repo("ts-app", tmp_path)
    inv = discover.discover(repo)
    assert inv["stacks"] == ["javascript"]
    pkg = inv["packages"][0]
    assert pkg["manager"] == "npm"
    assert pkg["lockfile"] == "package-lock.json"
    assert pkg["runtime_version"] == "22"
    assert pkg["runtime_version_source"] == ".nvmrc"
    assert pkg["test_runner"] == "vitest"
    assert pkg["has_tests"] is True


def test_discover_excludes_node_modules(tmp_path):
    repo = make_fixture_repo("ts-app", tmp_path, git=False)
    (repo / "node_modules" / "x").mkdir(parents=True)
    (repo / "node_modules" / "x" / "package.json").write_text("{}")
    (repo / ".venv" / "lib").mkdir(parents=True)
    (repo / ".venv" / "lib" / "x.py").write_text("x = 1\n")
    inv = discover.discover(repo)
    assert [p["path"] for p in inv["packages"]] == ["."]
    assert ".py" not in inv["file_counts"]
    assert ".json" in inv["file_counts"]
    assert inv["file_counts"][".json"] == 3  # package.json, package-lock.json, tsconfig.json


def test_discover_does_not_follow_symlinks(tmp_path):
    repo = make_fixture_repo("ts-app", tmp_path, git=False)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "evil.py").write_text("x = 1\n")
    os.symlink(outside, repo / "link")
    inv = discover.discover(repo)
    assert ".py" not in inv["file_counts"]


def test_discover_non_git_folder(tmp_path):
    repo = make_fixture_repo("py-app", tmp_path, git=False)
    inv = discover.discover(repo)
    assert inv["git"] == {"is_repo": False, "commit": None, "branch": None,
                          "dirty": False, "has_commits": False}


def test_discover_git_without_commits(tmp_path):
    repo = make_fixture_repo("py-app", tmp_path, git=False)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    git = discover.discover(repo)["git"]
    assert git["is_repo"] and not git["has_commits"] and git["commit"] is None


def test_discover_monorepo_two_packages(tmp_path):
    mono = tmp_path / "mono"
    (mono / "apps").mkdir(parents=True)
    shutil.copytree(make_fixture_repo("py-app", tmp_path / "a", git=False), mono / "apps" / "py-app")
    shutil.copytree(make_fixture_repo("ts-app", tmp_path / "b", git=False), mono / "apps" / "ts-app")
    inv = discover.discover(mono)
    assert [p["path"] for p in inv["packages"]] == ["apps/py-app", "apps/ts-app"]
    assert inv["stacks"] == ["javascript", "python"]
    assert inv["packages"][0]["test_runner"] == "pytest"
    assert inv["packages"][1]["test_runner"] == "vitest"
    assert inv["dockerfiles"] == ["apps/py-app/Dockerfile"]
    assert inv["github_workflows"] is True


def test_discover_reports_unsupported_stack(tmp_path):
    repo = make_fixture_repo("py-app", tmp_path, git=False)
    (repo / "go.mod").write_text("module x\n")
    assert "go" in discover.discover(repo)["unsupported_stacks"]


def test_discover_manager_and_runtime_rules(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nrequires-python = ">=3.10,<3.13"\ndependencies = ["openai>=1", "langchain-core"]\n')
    (tmp_path / "poetry.lock").write_text("")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package.json").write_text(json.dumps({
        "engines": {"node": ">=18.2"}, "scripts": {"test": "mocha"},
        "dependencies": {"@ai-sdk/openai": "1", "ai": "3"}}))
    (tmp_path / "web" / "pnpm-lock.yaml").write_text("")
    inv = discover.discover(tmp_path)
    py, js = inv["packages"][0], inv["packages"][1]
    assert (py["manager"], py["runtime_version"], py["runtime_version_source"]) == ("poetry", "3.10", "pyproject.toml")
    assert py["test_runner"] is None and py["has_tests"] is False
    assert (js["manager"], js["runtime_version"], js["test_runner"]) == ("pnpm", "18", "script")
    assert inv["ai_sdks"] == ["@ai-sdk/openai", "ai", "langchain-core", "openai"]


def test_discover_package_json_only_and_default_test_script(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps(
        {"scripts": {"test": 'echo "Error: no test specified" && exit 1'}}))
    pkg = discover.discover(tmp_path)["packages"][0]
    assert (pkg["manager"], pkg["lockfile"], pkg["test_runner"], pkg["runtime_version"]) == ("npm", None, None, None)


def test_discover_cli_writes_inventory_and_rotates(tmp_path):
    repo = make_fixture_repo("py-app", tmp_path)
    (repo / "audit" / "raw").mkdir(parents=True)
    (repo / "audit" / "report.md").write_text("old draft\n")
    r = subprocess.run([sys.executable, str(AUDIT_PY), "discover", "--project", str(repo)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    inv = json.loads((repo / "audit" / "raw" / "inventory.json").read_text())
    assert inv["packages"][0]["manager"] == "pip"
    assert inv["git"]["dirty"] is False  # audit/ itself does not make the tree dirty
    moved = list((repo / "audit" / "history").glob("*/report.md"))
    assert len(moved) == 1 and moved[0].read_text() == "old draft\n"
    assert "python" in r.stdout


def _git_cfg(repo, key, value):
    subprocess.run(["git", "config", key, value], cwd=repo, check=True)


def test_git_fsmonitor_not_executed(tmp_path):
    repo = make_fixture_repo("py-app", tmp_path)
    marker = tmp_path / "fsmonitor-ran"
    _git_cfg(repo, "core.fsmonitor", "touch %s; true" % marker)
    discover.discover(repo)
    assert not marker.exists()


def test_git_filter_driver_not_executed(tmp_path):
    repo = make_fixture_repo("py-app", tmp_path)
    marker = tmp_path / "filter-ran"
    (repo / ".gitattributes").write_text("* filter=evil\n")
    subprocess.run(["git", "add", ".gitattributes"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.name=f", "-c", "user.email=f@example.invalid",
                    "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "attrs"], cwd=repo, check=True)
    cmd = "touch %s; cat" % marker
    _git_cfg(repo, "filter.evil.clean", cmd)
    _git_cfg(repo, "filter.evil.process", cmd)
    os.utime(repo / "requirements.txt", (1, 1))  # stat-dirty tracked file
    inv = discover.discover(repo)
    assert not marker.exists()
    assert isinstance(inv["git"]["dirty"], bool)


def test_dirty_detects_modified_tracked_file(tmp_path):
    repo = make_fixture_repo("py-app", tmp_path)
    (repo / "requirements.txt").write_text("requests==2.19.1\n")
    assert discover.discover(repo)["git"]["dirty"] is True


def test_dirty_detects_deleted_untracked_and_staged(tmp_path):
    repo = make_fixture_repo("py-app", tmp_path)
    (repo / "Dockerfile").unlink()
    assert discover.discover(repo)["git"]["dirty"] is True
    repo = make_fixture_repo("py-app", tmp_path / "u")
    (repo / "new.txt").write_text("x")
    assert discover.discover(repo)["git"]["dirty"] is True
    repo = make_fixture_repo("py-app", tmp_path / "s")
    (repo / "new.txt").write_text("x")
    subprocess.run(["git", "add", "new.txt"], cwd=repo, check=True)
    assert discover.discover(repo)["git"]["dirty"] is True


def test_clean_repo_not_dirty(tmp_path):
    repo = make_fixture_repo("py-app", tmp_path)
    os.utime(repo / "requirements.txt", (1, 1))
    assert discover.discover(repo)["git"]["dirty"] is False


def test_discover_prunes_nested_excluded_dirs(tmp_path):
    repo = make_fixture_repo("py-app", tmp_path, git=False)
    baseline = discover.discover(repo)["file_counts"]
    for d in ("packages/x/node_modules/y", "apps/a/.venv/lib"):
        (repo / d).mkdir(parents=True)
    (repo / "packages/x/node_modules/y/package.json").write_text("{}")
    (repo / "apps/a/.venv/lib/mod.py").write_text("x = 1\n")
    inv = discover.discover(repo)
    assert [p["path"] for p in inv["packages"]] == ["."]
    assert inv["file_counts"] == baseline
