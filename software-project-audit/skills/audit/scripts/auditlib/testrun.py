"""Run a TestPlan on the developer's machine, in their prepared environment, in its own process group."""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import covtools, coverage_parse
from .hostenv import build_env, changed_paths, snapshot
from .paths import AuditPaths
from .testplan import TestPlan, pkg_slug, strip_coverage

LOG_CAP = 5 * 1024 * 1024
TRUNCATED = "\n[truncated]\n"
PHASES = ("setup", "test")
MAX_CHANGED_LISTED = 20


@dataclass
class TestResult:
    __test__ = False  # not a pytest class

    package_path: str
    status: str
    failed_phase: "str | None" = None
    exit_codes: dict = field(default_factory=dict)
    counts: "dict | None" = None
    coverage: "dict | None" = None
    raw_dir: str = ""
    notes: list = field(default_factory=list)
    runtime_version: "str | None" = None
    stripped_env: list = field(default_factory=list)
    coverage_tool_suggestion: "str | None" = None


class _Failed(Exception):
    def __init__(self, phase: str):
        super().__init__(phase)
        self.phase = phase


def _remove_symlinks(out: Path, res: TestResult) -> None:
    """Delete every symlink under out/ (project code controls what it writes there) and note each one."""
    for dirpath, dirnames, filenames in os.walk(str(out), followlinks=False):
        for name in sorted(dirnames + filenames):
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                os.unlink(full)
                res.notes.append("removed symlink from test output: %s"
                                 % Path(os.path.relpath(full, str(out))).as_posix())


def _parse_artifact(path: Path, out: Path, parser):
    """Parse one artifact; None when absent, outside out/, or unparsable."""
    try:
        inside = path.resolve().is_relative_to(out.resolve())
    except OSError:
        return None
    if not inside or path.is_symlink() or not path.is_file():
        return None
    try:
        return parser(path)
    except Exception as exc:  # untrusted input: ParseError, KeyError, ValueError, ...
        return exc  # the caller records only the exception type name


def _cap_log(log: Path) -> None:
    if log.stat().st_size <= LOG_CAP:
        return
    with open(str(log), "rb+") as fh:
        data = fh.read(LOG_CAP).decode("utf-8", errors="ignore").encode("utf-8")
        fh.seek(0)
        fh.write(data + TRUNCATED.encode("utf-8"))
        fh.truncate()


def _runtime_version(plan: TestPlan, env: dict) -> "str | None":
    exe = shutil.which("python" if plan.ecosystem == "python" else "node", path=env.get("PATH"))
    if not exe:
        return None
    try:
        r = subprocess.run([exe, "--version"], capture_output=True, text=True, env=env, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    text = (r.stdout or r.stderr or "").strip()
    if not text or r.returncode != 0:
        return None
    return text if plan.ecosystem == "python" else "Node %s" % text.lstrip("v")


def _kill_group(proc) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def run_test_plan(plan: TestPlan, paths: AuditPaths, base_env, timeout: int = 1200) -> TestResult:
    slug = pkg_slug(plan.package_path)
    out_dir = paths.raw / "tests" / slug
    out = out_dir / "out"
    res = TestResult(package_path=plan.package_path, status="failed", exit_codes={p: None for p in PHASES},
                     raw_dir=(Path("audit") / "raw" / "tests" / slug).as_posix(), notes=list(plan.notes))
    if out_dir.exists():  # never merge into another run's logs or artifacts
        res.notes.append("%s already exists; refusing to merge runs" % res.raw_dir)
        res.failed_phase = "setup"
        return res
    out.mkdir(parents=True)
    before = snapshot(paths.project)
    phase = "setup"
    try:
        if plan.temp_tools:
            tool = plan.temp_tools[0]
            name = "pytest-cov" if tool["kind"] == "python-target" else next(iter(tool["packages"]))
            res.coverage_tool_suggestion = covtools.suggestion(plan.manager, name, tool["packages"][name])
            res.notes += covtools.install(plan, paths, base_env)
        argv, artifacts = plan.argv, plan.artifacts
        if any(n.startswith("coverage not measured") for n in res.notes):
            # the tool is missing: run the confirmed command minus its coverage flags, so coverage is lost, not the run
            argv = strip_coverage(argv)
            artifacts = {k: v for k, v in artifacts.items() if k not in ("coveragepy", "istanbul")}
        env, res.stripped_env = build_env(base_env, plan.bin_dirs, plan.extra_env)
        res.runtime_version = _runtime_version(plan, env)
        res.exit_codes["setup"] = 0

        phase = "test"
        if not argv:
            res.notes.append("no test command")
            raise _Failed("test")
        log = out_dir / "test.log"
        with open(str(log), "wb") as fh:
            fh.write(("$ %s\n" % " ".join(argv)).encode("utf-8"))
            fh.flush()
            try:
                proc = subprocess.Popen(argv, cwd=plan.cwd, env=env, stdin=subprocess.DEVNULL, stdout=fh,
                                        stderr=subprocess.STDOUT, start_new_session=True)
            except OSError as exc:
                res.notes.append("could not start test command: %s" % type(exc).__name__)
                raise _Failed("test")
            try:
                code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                _kill_group(proc)
                proc.wait()
                res.notes.append("test timed out after %d s" % timeout)
                raise _Failed("test")
            finally:
                _kill_group(proc)  # test servers and workers must not outlive the run
        _cap_log(log)
        res.exit_codes["test"] = code

        _remove_symlinks(out, res)
        _collect(artifacts, out, res)
        if res.counts is None and code != 0 and ("junit" in artifacts or "jest_json" in artifacts):
            res.notes.append("test command exited %s and produced no readable test results" % code)
            raise _Failed("test")
        res.status = "completed" if (res.counts is not None and res.coverage is not None) else "partial"
        if res.counts is None:
            res.notes.append("no test counts: no readable result file")
        if res.coverage is None:
            res.notes.append("coverage missing")
    except _Failed as exc:
        res.status, res.failed_phase = "failed", exc.phase
    except Exception as exc:  # one broken package must not abort the whole audit
        res.status, res.failed_phase = "failed", phase
        res.notes.append("internal error: %s" % type(exc).__name__)
    finally:
        res.notes += covtools.remove(paths)
        changed = changed_paths(before, snapshot(paths.project))
        if changed:
            more = len(changed) - MAX_CHANGED_LISTED
            res.notes.append("tests modified the working tree: %s%s" % (
                ", ".join(changed[:MAX_CHANGED_LISTED]), " and %d more" % more if more > 0 else ""))
    return res


def _collect(artifacts: dict, out: Path, res: TestResult) -> None:
    """Fill res.counts / res.coverage from the declared artifacts."""
    for key, parser in (("jest_json", coverage_parse.parse_jest_json), ("junit", coverage_parse.parse_junit)):
        if key in artifacts and res.counts is None:
            got = _parse_artifact(Path(artifacts[key]), out, parser)
            if isinstance(got, dict):
                res.counts = got
            elif got is not None:
                res.notes.append("could not parse %s: %s" % (key, type(got).__name__))
    for key, parser in (("coveragepy", coverage_parse.parse_coveragepy),
                        ("istanbul", coverage_parse.parse_istanbul_summary)):
        if key in artifacts:
            got = _parse_artifact(Path(artifacts[key]), out, parser)
            if isinstance(got, dict):
                res.coverage = got
            elif got is not None:
                res.notes.append("could not parse %s: %s" % (key, type(got).__name__))
