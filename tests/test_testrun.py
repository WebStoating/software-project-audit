import json
import os
import signal
import sys
import time
from dataclasses import asdict
from pathlib import Path

import pytest

from auditlib import covtools, testrun
from auditlib.paths import AuditPaths
from auditlib.testplan import TestPlan

DATA = Path(__file__).resolve().parent / "data" / "test-output"


@pytest.fixture
def paths(tmp_path):
    p = AuditPaths.for_project(tmp_path / "proj")
    p.raw.mkdir(parents=True)
    return p


def _out(paths):
    return paths.raw / "tests" / "root" / "out"


def _plan(paths, script="", **kw):
    """A plan whose 'test command' is a small Python script; OUT is the absolute artifact directory."""
    out = _out(paths)
    bin_dir = paths.project / "fakebin"
    base = dict(package_path=".", ecosystem="python", manager="pip", runner="pytest", cwd=str(paths.project),
                argv=[sys.executable, "-c", "OUT = %r\n" % str(out) + script],
                environment={"kind": "venv", "path": str(paths.project / ".venv")}, bin_dirs=[str(bin_dir)],
                extra_env={"CI": "true", "PYTHONDONTWRITEBYTECODE": "1", "COVERAGE_FILE": str(out / ".coverage")},
                artifacts={"junit": str(out / "junit.xml"), "coveragepy": str(out / "coverage.json")})
    base.update(kw)
    return TestPlan(**base)


COPY = ("import shutil, sys\n"
        "for name in %r: shutil.copy(%r + '/' + name, OUT + '/' + name.replace('pytest-junit', 'junit')"
        ".replace('coveragepy', 'coverage'))\n")


def _copy(*names, exit_code=0):
    return COPY % (list(names), str(DATA)) + "sys.exit(%d)\n" % exit_code


def _run(plan, paths, base_env=None, **kw):
    return testrun.run_test_plan(plan, paths, base_env if base_env is not None else {"PATH": os.environ["PATH"]}, **kw)


def test_runs_in_cwd_with_built_env(paths):
    script = ("import json, os\njson.dump({'cwd': os.getcwd(), 'ci': os.environ.get('CI'), "
              "'path': os.environ['PATH']}, open(OUT + '/probe.json', 'w'))\n")
    _run(_plan(paths, script), paths)
    probe = json.loads((_out(paths) / "probe.json").read_text())
    assert os.path.realpath(probe["cwd"]) == os.path.realpath(str(paths.project))
    assert probe["ci"] == "true"
    assert probe["path"].split(os.pathsep)[0] == str(paths.project / "fakebin")


def test_credentials_not_visible_to_tests(paths):
    script = "import json, os\njson.dump({'gh': 'GH_TOKEN' in os.environ}, open(OUT + '/probe.json', 'w'))\n"
    res = _run(_plan(paths, script), paths, {"PATH": os.environ["PATH"], "GH_TOKEN": "fake"})
    assert json.loads((_out(paths) / "probe.json").read_text()) == {"gh": False}
    assert res.stripped_env == ["GH_TOKEN"]


def test_timeout_kills_process_group(paths):
    script = ("import subprocess, time\np = subprocess.Popen(['sleep', '60'])\n"
              "open(OUT + '/child.pid', 'w').write(str(p.pid))\ntime.sleep(60)\n")
    res = _run(_plan(paths, script), paths, timeout=2)
    assert res.status == "failed" and res.failed_phase == "test"
    assert "test timed out after 2 s" in res.notes
    pid = int((_out(paths) / "child.pid").read_text())
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        os.kill(pid, signal.SIGKILL)
        pytest.fail("child process survived the timeout")


def test_working_tree_changes_reported(paths):
    script = "import os\nopen(os.path.join(os.getcwd(), 'created.db'), 'w').write('x')\n"
    res = _run(_plan(paths, script), paths)
    assert "tests modified the working tree: created.db" in res.notes


def test_no_working_tree_note_when_clean(paths):
    res = _run(_plan(paths, _copy("pytest-junit.xml", "coveragepy.json")), paths)
    assert not any(n.startswith("tests modified the working tree") for n in res.notes)


def test_completed_parses_counts_and_coverage(paths):
    res = _run(_plan(paths, _copy("pytest-junit.xml", "coveragepy.json", exit_code=1)), paths)
    assert res.status == "completed" and res.failed_phase is None
    assert res.counts == {"passed": 2, "failed": 1, "skipped": 1, "errors": 1}
    assert res.coverage["branch_pct"] == 100.0
    assert res.exit_codes == {"setup": 0, "test": 1}
    assert res.raw_dir == "audit/raw/tests/root"


def test_missing_coverage_is_partial(paths):
    res = _run(_plan(paths, _copy("pytest-junit.xml")), paths)
    assert res.status == "partial" and res.counts["passed"] == 2 and res.coverage is None
    assert "coverage missing" in res.notes


def test_no_results_and_nonzero_exit_is_failed(paths):
    res = _run(_plan(paths, "import sys\nsys.exit(2)\n"), paths)
    assert res.status == "failed" and res.failed_phase == "test"


def test_command_that_cannot_start_is_failed(paths):
    res = _run(_plan(paths, argv=["definitely-not-a-command-xyz"]), paths)
    assert res.status == "failed" and res.failed_phase == "test"
    assert any(n.startswith("could not start test command") for n in res.notes)


def test_symlinked_artifact_is_not_parsed(paths, tmp_path):
    host_file = tmp_path / "host.xml"
    host_file.write_text((DATA / "pytest-junit.xml").read_text())
    script = "import os\nos.symlink(%r, OUT + '/junit.xml')\n" % str(host_file)
    res = _run(_plan(paths, script), paths)
    assert res.counts is None and res.status != "completed"
    assert "removed symlink from test output: junit.xml" in res.notes
    assert host_file.exists()


def test_test_log_is_capped(paths):
    res = _run(_plan(paths, "import sys\nsys.stdout.write('x' * (6 * 1024 * 1024))\n"), paths)
    text = (paths.project / res.raw_dir / "test.log").read_text()
    assert len(text) <= 5 * 1024 * 1024 + 100 and text.endswith("\n[truncated]\n")


def test_existing_out_dir_fails_package_instead_of_merging(paths):
    (paths.raw / "tests" / "root").mkdir(parents=True)
    res = _run(_plan(paths, "open(OUT + '/ran', 'w')\n"), paths)
    assert res.status == "failed" and res.failed_phase == "setup"
    assert any("already exists" in n for n in res.notes)
    assert not (_out(paths) / "ran").exists()


def test_temp_tools_removed_even_when_test_raises(paths, monkeypatch):
    calls = []
    monkeypatch.setattr(covtools, "install", lambda plan, p, env: calls.append("install") or [])
    monkeypatch.setattr(covtools, "remove", lambda p: calls.append("remove") or [])

    def boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(testrun.subprocess, "Popen", boom)
    tool = {"kind": "python-target", "target": str(paths.raw / ".tools" / "python" / "root"), "link": None,
            "packages": {"pytest-cov": "7.1.0", "coverage": "7.10.7"}}
    res = _run(_plan(paths, "", temp_tools=[tool]), paths)
    assert res.status == "failed" and calls == ["install", "remove"]


def test_removal_warnings_reach_notes(paths, monkeypatch):
    monkeypatch.setattr(covtools, "remove", lambda p: ["WARNING: x left in place"])
    res = _run(_plan(paths, ""), paths)
    assert "WARNING: x left in place" in res.notes


def test_coverage_tool_suggestion_set_when_temp_tool_used(paths, monkeypatch):
    monkeypatch.setattr(covtools, "install", lambda plan, p, env: [])
    plan = _plan(paths, _copy("pytest-junit.xml", "coveragepy.json"), manager="uv",
                 temp_tools=[{"kind": "python-target", "target": str(paths.raw / ".tools" / "python" / "root"),
                              "link": None, "packages": {"pytest-cov": "7.1.0", "coverage": "7.10.7"}}])
    res = _run(plan, paths)
    assert res.coverage_tool_suggestion == covtools.suggestion("uv", "pytest-cov", "7.1.0")


def test_no_suggestion_without_temp_tools(paths):
    assert _run(_plan(paths, ""), paths).coverage_tool_suggestion is None


def test_runtime_version_recorded(paths):
    bin_dir = paths.project / "fakebin"
    bin_dir.mkdir(parents=True)
    os.symlink(sys.executable, str(bin_dir / "python"))
    res = _run(_plan(paths, ""), paths)
    assert res.runtime_version == "Python %d.%d.%d" % sys.version_info[:3]


def test_result_json_has_no_host_paths(paths):
    res = _run(_plan(paths, _copy("pytest-junit.xml", "coveragepy.json")), paths)
    assert str(paths.project) not in json.dumps(asdict(res))


def test_failed_coverage_install_runs_without_coverage_flags(paths, monkeypatch):
    monkeypatch.setattr(covtools, "install", lambda plan, p, env: ["coverage not measured: no pip in venv"])
    script = "import json, sys\njson.dump(sys.argv[1:], open(OUT + '/argv.json', 'w'))\n" + _copy("pytest-junit.xml")
    tool = {"kind": "python-target", "target": str(paths.raw / ".tools" / "python" / "root"), "link": None,
            "packages": {"pytest-cov": "7.1.0", "coverage": "7.10.7"}}
    plan = _plan(paths, script, temp_tools=[tool])
    plan.argv += ["--cov=.", "--cov-branch", "--cov-report=json:x", "-q"]
    res = _run(plan, paths)
    assert json.loads((_out(paths) / "argv.json").read_text()) == ["-q"]
    assert res.status == "partial" and res.counts["passed"] == 2
