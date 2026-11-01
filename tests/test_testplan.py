import json
import os
from pathlib import Path

from helpers import SKILL_DIR

import pytest

from auditlib import discover, testplan
from helpers import make_fixture_repo

VERSIONS = json.loads((SKILL_DIR
                       / "assets" / "tool-versions.json").read_text(encoding="utf-8"))
PINS = VERSIONS["coverage_tools"]


def _pkg(path=".", **kw):
    p = {"path": path, "ecosystem": "python", "manager": "pip", "manifest": "requirements.txt",
         "lockfile": None, "runtime_version": None, "runtime_version_source": None,
         "test_runner": "pytest", "has_tests": True}
    p.update(kw)
    return p


def _js(path=".", runner="vitest", manager="npm"):
    return _pkg(path, ecosystem="javascript", manager=manager, manifest="package.json", test_runner=runner)


def _venv(d: Path, pytest_cov=True, python=True) -> Path:
    v = d / ".venv"
    (v / "bin").mkdir(parents=True)
    (v / "pyvenv.cfg").write_text("home = /usr/bin\n")
    if python:
        exe = v / "bin" / "python"
        exe.write_text("#!/bin/sh\n")
        exe.chmod(0o755)
    site = v / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    if pytest_cov:
        (site / "pytest_cov").mkdir()
    return v


def _node_modules(d: Path, runner="vitest", provider=True, version="2.1.9") -> Path:
    nm = d / "node_modules"
    (nm / ".bin").mkdir(parents=True)
    exe = nm / ".bin" / runner
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    (nm / runner).mkdir()
    (nm / runner / "package.json").write_text(json.dumps({"version": version}))
    if provider:
        (nm / "@vitest" / "coverage-v8").mkdir(parents=True)
    return nm


def _plan(project, *pkgs, environ=None, **kw):
    inv = {"project": str(project), "packages": list(pkgs)}
    return testplan.plan_tests(inv, project, VERSIONS, environ or {}, project / "audit" / "raw" / "tests", **kw)


def test_root_venv_found_and_pytest_cov_present(tmp_path):
    v = _venv(tmp_path)
    plans, skipped = _plan(tmp_path, _pkg())
    assert skipped == []
    (p,) = plans
    out = tmp_path / "audit" / "raw" / "tests" / "root" / "out"
    assert p.argv[:3] == [str(v / "bin" / "python"), "-m", "pytest"]
    assert p.argv[3:5] == ["-p", "no:cacheprovider"]
    assert "--cov-report=json:%s" % (out / "coverage.json") in p.argv
    assert "--junitxml=%s" % (out / "junit.xml") in p.argv
    assert p.cwd == str(tmp_path)
    assert p.temp_tools == []
    assert p.environment == {"kind": "venv", "path": str(v)}
    assert p.bin_dirs == [str(v / "bin")]
    assert p.extra_env["VIRTUAL_ENV"] == str(v)
    assert p.artifacts == {"junit": str(out / "junit.xml"), "coveragepy": str(out / "coverage.json")}


def test_missing_pytest_cov_adds_python_target_tool(tmp_path):
    _venv(tmp_path, pytest_cov=False)
    (p,), _ = _plan(tmp_path, _pkg())
    target = tmp_path / "audit" / "raw" / ".tools" / "python" / "root"
    assert p.temp_tools == [{"kind": "python-target", "target": str(target), "link": None,
                             "packages": {"pytest-cov": PINS["pytest-cov"], "coverage": PINS["coverage"]}}]
    assert p.extra_env["PYTHONPATH"] == str(target)
    assert any(a.startswith("--cov-report=json:") for a in p.argv)


def test_package_venv_wins_over_root_venv(tmp_path):
    _venv(tmp_path)
    (tmp_path / "svc").mkdir()
    sv = _venv(tmp_path / "svc")
    (p,), _ = _plan(tmp_path, _pkg("svc"))
    assert p.environment["path"] == str(sv) and p.cwd == str(tmp_path / "svc")


def test_virtual_env_used_as_external(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    (tmp_path / "elsewhere").mkdir()
    ext = _venv(tmp_path / "elsewhere")
    (p,), _ = _plan(project, _pkg(), environ={"VIRTUAL_ENV": str(ext)})
    assert p.environment == {"kind": "external", "path": str(ext)}
    assert p.argv[0] == str(ext / "bin" / "python")


def test_pythons_override_used_as_external_and_wins(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    _venv(project)
    (tmp_path / "other").mkdir()
    ext = _venv(tmp_path / "other")
    (p,), _ = _plan(project, _pkg(), pythons={".": str(ext / "bin" / "python")})
    assert p.environment == {"kind": "external", "path": str(ext)}
    assert p.argv[0] == str(ext / "bin" / "python")


def test_venv_without_python_is_not_set_up(tmp_path):
    _venv(tmp_path, python=False)
    plans, skipped = _plan(tmp_path, _pkg())
    assert plans == []
    assert skipped == [{"package_path": ".", "reason": "project not set up locally: .venv has no Python interpreter"}]


def test_no_venv_is_not_set_up(tmp_path):
    plans, skipped = _plan(tmp_path, _pkg())
    assert plans == [] and skipped[0]["reason"] == "project not set up locally: no virtual environment found"


def test_node_vitest_with_provider(tmp_path):
    nm = _node_modules(tmp_path)
    (p,), _ = _plan(tmp_path, _js())
    out = tmp_path / "audit" / "raw" / "tests" / "root" / "out"
    assert p.argv[:2] == [str(nm / ".bin" / "vitest"), "run"]
    assert "--coverage.reportsDirectory=%s" % (out / "coverage") in p.argv
    assert "--outputFile.junit=%s" % (out / "junit.xml") in p.argv
    assert p.temp_tools == []
    assert p.environment == {"kind": "node_modules", "path": str(nm)}
    assert p.bin_dirs == [str(nm / ".bin")]
    assert p.artifacts == {"junit": str(out / "junit.xml"), "istanbul": str(out / "coverage" / "coverage-summary.json")}


def test_node_vitest_without_provider_adds_vitest_tool(tmp_path):
    nm = _node_modules(tmp_path, provider=False)
    (p,), _ = _plan(tmp_path, _js())
    assert p.temp_tools == [{"kind": "vitest-provider", "packages": {"@vitest/coverage-v8": "2.1.9"},
                             "target": str(tmp_path / "audit" / "raw" / ".tools" / "node" / "root"),
                             "link": str(nm / "@vitest" / "coverage-v8")}]


def test_workspace_root_node_modules_used_for_subpackage(tmp_path):
    nm = _node_modules(tmp_path)
    (tmp_path / "web").mkdir()
    (p,), _ = _plan(tmp_path, _js("web"))
    assert p.argv[0] == str(nm / ".bin" / "vitest") and p.cwd == str(tmp_path / "web")


def test_subpackage_bin_dirs_include_package_and_root(tmp_path):
    root_nm = _node_modules(tmp_path)
    (tmp_path / "web").mkdir()
    pkg_nm = _node_modules(tmp_path / "web")
    (p,), _ = _plan(tmp_path, _js("web"))
    assert p.bin_dirs == [str(pkg_nm / ".bin"), str(root_nm / ".bin")]
    assert p.argv[0] == str(pkg_nm / ".bin" / "vitest")


def test_node_without_node_modules_is_not_set_up(tmp_path):
    plans, skipped = _plan(tmp_path, _js())
    assert plans == []
    assert skipped == [{"package_path": ".", "reason": "project not set up locally: node_modules not found"}]


def test_jest_gets_cache_directory_under_out(tmp_path):
    _node_modules(tmp_path, runner="jest", provider=False)
    (p,), _ = _plan(tmp_path, _js(runner="jest"))
    out = tmp_path / "audit" / "raw" / "tests" / "root" / "out"
    assert "--cacheDirectory=%s" % (out / "jest-cache") in p.argv
    assert p.temp_tools == []
    assert p.artifacts == {"jest_json": str(out / "jest.json"),
                           "istanbul": str(out / "coverage" / "coverage-summary.json")}


def test_script_runner_runs_manager_test(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (p,), _ = _plan(tmp_path, _js(runner="script", manager="pnpm"))
    assert p.argv == ["pnpm", "test"]
    assert "coverage not collected: unknown runner" in p.notes


def test_override_is_split_without_shell(tmp_path):
    _venv(tmp_path)
    (p,), _ = _plan(tmp_path, _pkg(), overrides={".": "pytest -q -k 'a b'"})
    assert p.argv == ["pytest", "-q", "-k", "a b"]
    assert p.artifacts == {} and p.temp_tools == []
    assert testplan.OVERRIDE_NOTE in p.notes


@pytest.mark.parametrize("cmd", ["env A=1 pytest", "A=1 pytest", "A=1 B=2 pytest"])
def test_override_with_env_assignment_rejected(cmd):
    with pytest.raises(ValueError, match="settings must come from the developer's setup"):
        testplan.parse_override(cmd)


def test_override_python_still_needs_venv(tmp_path):
    plans, skipped = _plan(tmp_path, _pkg(), overrides={".": "pytest"})
    assert plans == [] and skipped[0]["reason"].startswith("project not set up locally")


def test_override_for_package_without_runner(tmp_path):
    _venv(tmp_path)
    (p,), _ = _plan(tmp_path, _pkg(test_runner=None), overrides={".": "tox"})
    assert p.argv == ["tox"]


def test_extra_env_has_ci_bytecode_and_coverage_file(tmp_path):
    _venv(tmp_path)
    (p,), _ = _plan(tmp_path, _pkg())
    out = tmp_path / "audit" / "raw" / "tests" / "root" / "out"
    assert p.extra_env["CI"] == "true"
    assert p.extra_env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert p.extra_env["COVERAGE_FILE"] == str(out / ".coverage")


def test_plan_digest_changes_with_argv_or_environment(tmp_path):
    _venv(tmp_path)
    plans, skipped = _plan(tmp_path, _pkg())
    d1 = testplan.plan_digest(plans, skipped)
    assert d1 == testplan.plan_digest(*_plan(tmp_path, _pkg()))
    assert d1 != testplan.plan_digest(*_plan(tmp_path, _pkg(), overrides={".": "pytest"}))
    plans[0].environment = {"kind": "external", "path": "/x"}
    assert d1 != testplan.plan_digest(plans, skipped)


def test_to_json_has_no_host_paths(tmp_path):
    project = tmp_path / "my prø ject"
    project.mkdir()
    _venv(project, pytest_cov=False)
    (p,), _ = _plan(project, _pkg())
    text = json.dumps(p.to_json(project, str(tmp_path)))
    assert str(project) not in text and str(tmp_path) not in text
    assert "<project>/.venv/bin/python" in text


def test_cap_and_no_tests_kept(tmp_path):
    _venv(tmp_path)
    pkgs = [_pkg("p%02d" % i) for i in range(11, -1, -1)]
    pkgs.append(_pkg("zz", has_tests=False, test_runner=None))
    plans, skipped = _plan(tmp_path, *pkgs)
    assert [p.package_path for p in plans] == ["p%02d" % i for i in range(10)]
    reasons = {s["package_path"]: s["reason"] for s in skipped}
    assert reasons == {"p10": "cap of 10 reached", "p11": "cap of 10 reached", "zz": "no tests"}


def test_no_runner_and_unknown_manager_skipped(tmp_path):
    plans, skipped = _plan(tmp_path, _pkg("a", test_runner=None), _js("b", runner="script", manager="bun"))
    assert plans == []
    assert skipped == [{"package_path": "a", "reason": "no test runner determined"},
                       {"package_path": "b", "reason": "no test runner determined"}]


def test_plan_py_fixture_with_venv(tmp_path):
    repo = make_fixture_repo("py-app", tmp_path)
    _venv(repo)
    plans, skipped = _plan(repo, *discover.discover(repo)["packages"])
    assert skipped == [] and len(plans) == 1 and plans[0].runner == "pytest"


def test_pkg_slug_unchanged():
    assert testplan.pkg_slug(".") == "root" and testplan.pkg_slug("web") == "web"
    assert testplan.pkg_slug("a/b").startswith("a__b-") and os.sep not in testplan.pkg_slug("../x")


def test_strip_coverage_removes_only_coverage_flags():
    argv = ["vitest", "run", "--coverage", "--coverage.reporter=json-summary", "--reporter=junit",
            "py", "--cov=.", "--cov-branch", "--cov-report=json:x", "-q"]
    assert testplan.strip_coverage(argv) == ["vitest", "run", "--reporter=junit", "py", "-q"]


def test_vitest_unknown_version_drops_coverage_flags(tmp_path):
    nm = _node_modules(tmp_path, provider=False)
    (nm / "vitest" / "package.json").write_text("not json")
    (p,), _ = _plan(tmp_path, _js())
    assert not any(a.startswith("--cov") for a in p.argv)
    assert "coverage not measured: vitest version unknown" in p.notes and p.temp_tools == []


def test_broken_project_venv_does_not_fall_through_to_active_venv(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    _venv(project, python=False)
    (tmp_path / "other").mkdir()
    ext = _venv(tmp_path / "other")
    plans, skipped = _plan(project, _pkg(), environ={"VIRTUAL_ENV": str(ext)})
    assert plans == []
    assert skipped == [{"package_path": ".", "reason": "project not set up locally: .venv has no Python interpreter"}]
