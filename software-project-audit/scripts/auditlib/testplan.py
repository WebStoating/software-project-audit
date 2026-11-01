"""Per-package plans for running unit tests with coverage in the developer's own environment (pure logic)."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .hostenv import redact

MAX_RUNS = 10
OVERRIDE_NOTE = "test command supplied by agent; coverage may not be collected"
NO_VENV = "project not set up locally: no virtual environment found"
NO_NODE_MODULES = "project not set up locally: node_modules not found"
MANAGERS = frozenset({"uv", "poetry", "pipenv", "pip", "npm", "pnpm", "yarn"})
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


@dataclass
class TestPlan:
    __test__ = False  # not a pytest class

    package_path: str
    ecosystem: str
    manager: str
    runner: str
    cwd: str
    argv: list = field(default_factory=list)
    environment: dict = field(default_factory=dict)
    bin_dirs: list = field(default_factory=list)
    extra_env: dict = field(default_factory=dict)
    temp_tools: list = field(default_factory=list)
    artifacts: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)

    def to_json(self, project, home: str) -> dict:
        """The plan with the project root shown as <project> and home as ~ (no absolute host paths)."""
        def walk(v):
            if isinstance(v, str):
                return redact(v, project, home)
            if isinstance(v, list):
                return [walk(x) for x in v]
            if isinstance(v, dict):
                return {k: walk(x) for k, x in v.items()}
            return v
        return walk(asdict(self))


def pkg_slug(package_path: str) -> str:
    """Filesystem-safe directory name for a package path ("." -> root, "/" -> "__")."""
    if package_path in ("", "."):
        return "root"
    slug = re.sub(r"[^A-Za-z0-9._-]", "_", package_path.replace("/", "__"))
    stripped = slug.lstrip(".")
    slug = "_" * (len(slug) - len(stripped)) + stripped
    if slug != package_path:  # sanitizing may merge distinct paths; the hash keeps them apart
        slug += "-" + hashlib.sha256(package_path.encode("utf-8")).hexdigest()[:8]
    return slug


def parse_override(command: str) -> list:
    """Split an agent-supplied test command into argv; settings must never be passed this way."""
    argv = shlex.split(command)
    if not argv:
        raise ValueError("empty test command")
    if argv[0] == "env" or _ASSIGNMENT.match(argv[0]):
        raise ValueError("settings must come from the developer's setup, not --command: %r" % command)
    return argv


def strip_coverage(argv: list) -> list:
    """The same command without its coverage flags (pytest-cov --cov*, vitest/jest --coverage*)."""
    return [a for a in argv if not a.startswith("--cov")]


def _python_of(venv: Path) -> "Path | None":
    for rel in (("bin", "python"), ("Scripts", "python.exe")):
        exe = venv.joinpath(*rel)
        if exe.is_file() and os.access(str(exe), os.X_OK):
            return exe
    return None


def _venv_in(d: Path) -> tuple:
    """(venv, broken): a virtual environment directly inside d (.venv and venv first) with a usable
    interpreter, else the name of one that has pyvenv.cfg but no interpreter."""
    try:
        names = sorted(c.name for c in d.iterdir() if c.is_dir())
    except OSError:
        return None, None
    names.sort(key=lambda n: (n not in (".venv", "venv"), n != ".venv", n))
    broken = None
    for name in names:
        v = d / name
        if (v / "pyvenv.cfg").is_file():
            if _python_of(v):
                return v, None
            broken = broken or name
    return None, broken


def _find_python(project: Path, pkg_dir: Path, path: str, environ, pythons: dict):
    """Return (interpreter, environment dict) or (None, skip reason)."""
    explicit = pythons.get(path)
    if explicit:
        exe = Path(explicit)
        venv = exe.parent.parent
        return exe, {"kind": "external", "path": str(venv if (venv / "pyvenv.cfg").is_file() else exe.parent)}
    for d in (pkg_dir, project):
        v, broken = _venv_in(d)
        if v:
            return _python_of(v), {"kind": "venv", "path": str(v)}
        if broken:  # never fall through to an unrelated active venv
            return None, "project not set up locally: %s has no Python interpreter" % broken
    active = environ.get("VIRTUAL_ENV")
    if active and (Path(active) / "pyvenv.cfg").is_file() and _python_of(Path(active)):
        v = Path(active)
        inside = str(v.resolve()).startswith(str(project.resolve()) + os.sep)
        return _python_of(v), {"kind": "venv" if inside else "external", "path": str(v)}
    return None, NO_VENV


def _has_pytest_cov(venv: Path) -> bool:
    return any(venv.glob("lib/python*/site-packages/pytest_cov")) or (venv / "Lib" / "site-packages" / "pytest_cov").is_dir()


def _plan_python(pkg, project, pkg_dir, out, tools, environ, pythons, override, pins):
    exe, environment = _find_python(project, pkg_dir, pkg["path"], environ, pythons)
    if exe is None:
        return None, environment
    bin_dir = str(exe.parent)
    plan = TestPlan(pkg["path"], "python", pkg["manager"], pkg.get("test_runner") or "custom", str(pkg_dir),
                    environment=environment, bin_dirs=[bin_dir])
    if environment["kind"] != "external" or (Path(environment["path"]) / "pyvenv.cfg").is_file():
        plan.extra_env["VIRTUAL_ENV"] = environment["path"]
    if override:
        plan.argv = override
        return plan, None
    plan.argv = [str(exe), "-m", "pytest", "-p", "no:cacheprovider", "--cov=.", "--cov-branch",
                 "--cov-report=json:%s" % (out / "coverage.json"), "--junitxml=%s" % (out / "junit.xml"), "-q"]
    plan.artifacts = {"junit": str(out / "junit.xml"), "coveragepy": str(out / "coverage.json")}
    if not _has_pytest_cov(Path(environment["path"])):
        target = tools / "python" / out.parent.name
        plan.temp_tools.append({"kind": "python-target", "target": str(target), "link": None,
                                "packages": {"pytest-cov": pins["pytest-cov"], "coverage": pins["coverage"]}})
        plan.extra_env["PYTHONPATH"] = str(target)
    return plan, None


def _node_dirs(project: Path, pkg_dir: Path) -> list:
    dirs = [pkg_dir / "node_modules"]
    if pkg_dir != project:
        dirs.append(project / "node_modules")
    return [d for d in dirs if d.is_dir()]


def _plan_node(pkg, project, pkg_dir, out, tools, override):
    nms = _node_dirs(project, pkg_dir)
    if not nms:
        return None, NO_NODE_MODULES
    runner = pkg.get("test_runner") or "custom"
    plan = TestPlan(pkg["path"], "javascript", pkg["manager"], runner, str(pkg_dir),
                    bin_dirs=[str(nm / ".bin") for nm in nms if (nm / ".bin").is_dir()])
    home = next((nm for nm in nms if (nm / ".bin" / runner).is_file()), nms[0])
    plan.environment = {"kind": "node_modules", "path": str(home)}
    if override:
        plan.argv = override
        return plan, None
    if runner == "script":
        plan.argv = [pkg["manager"], "test"]
        plan.notes.append("coverage not collected: unknown runner")
        return plan, None
    exe = home / ".bin" / runner
    if not exe.is_file():
        return None, "project not set up locally: %s not found in node_modules" % runner
    summary = str(out / "coverage" / "coverage-summary.json")
    if runner == "vitest":
        plan.argv = [str(exe), "run", "--coverage", "--coverage.reportOnFailure", "--coverage.reporter=json-summary",
                     "--coverage.reportsDirectory=%s" % (out / "coverage"), "--reporter=default",
                     "--reporter=junit", "--outputFile.junit=%s" % (out / "junit.xml")]
        plan.artifacts = {"junit": str(out / "junit.xml"), "istanbul": summary}
        if not any((home / "@vitest" / p).is_dir() for p in ("coverage-v8", "coverage-istanbul")):
            try:
                version = json.loads((home / "vitest" / "package.json").read_text(encoding="utf-8"))["version"]
            except (OSError, ValueError, KeyError, TypeError):
                version = None
            if version:
                plan.temp_tools.append({"kind": "vitest-provider", "packages": {"@vitest/coverage-v8": version},
                                        "target": str(tools / "node" / out.parent.name),
                                        "link": str(home / "@vitest" / "coverage-v8")})
            else:
                plan.argv = strip_coverage(plan.argv)
                del plan.artifacts["istanbul"]
                plan.notes.append("coverage not measured: vitest version unknown")
    else:  # jest
        plan.argv = [str(exe), "--ci", "--coverage", "--coverageReporters=json-summary",
                     "--coverageDirectory=%s" % (out / "coverage"), "--cacheDirectory=%s" % (out / "jest-cache"),
                     "--json", "--outputFile=%s" % (out / "jest.json")]
        plan.artifacts = {"jest_json": str(out / "jest.json"), "istanbul": summary}
    return plan, None


def plan_tests(inventory: dict, project: Path, versions: dict, environ, out_root: Path,
               overrides: "dict | None" = None, pythons: "dict | None" = None) -> tuple:
    """Return (plans, skipped). Packages are processed in package_path order so the cap is reproducible."""
    project = Path(project)
    overrides, pythons = overrides or {}, pythons or {}
    tools = Path(out_root).parent / ".tools"
    plans, skipped = [], []
    for pkg in sorted(inventory["packages"], key=lambda p: (p["path"], p["ecosystem"])):
        path = pkg["path"]
        override = parse_override(overrides[path]) if path in overrides else None
        if not pkg.get("has_tests"):
            skipped.append({"package_path": path, "reason": "no tests"})
            continue
        if (not pkg.get("test_runner") and not override) or pkg["manager"] not in MANAGERS:
            skipped.append({"package_path": path, "reason": "no test runner determined"})
            continue
        if len(plans) >= MAX_RUNS:
            skipped.append({"package_path": path, "reason": "cap of 10 reached"})
            continue
        pkg_dir = project if path in ("", ".") else project / path
        out = Path(out_root) / pkg_slug(path) / "out"
        if pkg["ecosystem"] == "python":
            plan, reason = _plan_python(pkg, project, pkg_dir, out, tools, environ, pythons, override,
                                        versions["coverage_tools"])
        else:
            plan, reason = _plan_node(pkg, project, pkg_dir, out, tools, override)
        if plan is None:
            skipped.append({"package_path": path, "reason": reason})
            continue
        plan.extra_env.update({"CI": "true", "PYTHONDONTWRITEBYTECODE": "1",
                               "COVERAGE_FILE": str(out / ".coverage")})
        if override:
            plan.notes.append(OVERRIDE_NOTE)
        plans.append(plan)
    return plans, skipped


def plan_digest(plans: list, skipped: list) -> str:
    """Fingerprint of everything that decides what runs on the host; --run refuses if it changed."""
    keys = ("package_path", "cwd", "argv", "environment", "bin_dirs", "extra_env", "temp_tools")
    data = {"plans": [{k: getattr(p, k) for k in keys} for p in plans], "skipped": skipped}
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()
