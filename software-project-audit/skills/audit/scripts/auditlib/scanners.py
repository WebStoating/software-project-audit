"""Scanner registry and runner: one container run per tool, one ledger record per tool.

A scanner hit is a lead, not a finding, and a failed tool must never look like a clean result.
Exit codes below come from each tool's documentation for the version pinned in
assets/tool-versions.json; anything not listed is a failure.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from . import dockerutil, parsers
from .discover import EXCLUDED_DIRS
from .ledger import append_run
from .models import RunRecord
from .paths import AuditPaths

SRC = "/src"
OUT = "/out"
VERSION_TIMEOUT = 120
STDERR_TAIL = 400
ZIZMOR_MODE = "offline (no GitHub token; online audits skipped)"
_EXCLUDED = sorted(EXCLUDED_DIRS)


@dataclass
class ScannerSpec:
    name: str
    applies: Callable[[dict], bool]
    argv: Callable[[dict], list]
    output: str                      # path under raw/scanners/
    ok_codes: frozenset              # exit codes meaning "ran, nothing reported"
    findings_codes: frozenset        # exit codes meaning "ran, reported findings"
    parse: Callable[[Path], list]
    version_argv: list
    capture_stdout: bool = False     # the tool prints its report; the runner stores it at `output`
    scrub_keys: frozenset = frozenset()  # source-text keys removed from the stored raw JSON
    partial_check: Optional[Callable[[Path], Optional[str]]] = None
    notes: Optional[Callable[[dict], dict]] = None   # extra counts, e.g. the mode that ran
    prepare: Optional[Callable[[Path], None]] = None  # write helper files into raw/scanners
    na_reason: str = "no matching files or stack in the project inventory"


# ---- applicability ----------------------------------------------------------------------------
def _stack(*names):
    return lambda inv: any(n in (inv.get("stacks") or []) for n in names)


def _any(*keys):
    return lambda inv: any(inv.get(k) for k in keys)


def _semgrep_applies(inv):
    return _stack("python", "javascript")(inv) or _any("dockerfiles", "github_workflows")(inv)


def _has_manifest(inv):
    return any(p.get("manifest") or p.get("lockfile") for p in inv.get("packages") or [])


def _trivy_applies(inv):
    return _has_manifest(inv) or _any("dockerfiles", "compose_files", "iac_files", "k8s_files")(inv)


def _always(inv):
    return True


# ---- argv builders (inside the container: project at /src, output at /out) --------------------
def _semgrep_argv(inv):
    argv = ["semgrep"]
    for pack in dockerutil.load_versions()["semgrep_packs"]:
        argv += ["--config", "/rules/%s.yml" % pack.replace("/", "-")]
    argv += ["--json", "--metrics=off", "--output", OUT + "/semgrep.json"]
    for d in _EXCLUDED:
        argv += ["--exclude", d]
    return argv + [SRC]


def _bandit_argv(inv):
    return ["bandit", "-r", "-f", "json", "-o", OUT + "/bandit.json",
            "-x", ",".join("*/%s/*" % d for d in _EXCLUDED), SRC]


def _osv_argv(inv):
    argv = ["osv-scanner", "scan", "source", "-r", "--format", "json", "--output", OUT + "/osv.json"]
    for d in _EXCLUDED:
        argv += ["--x-exclude", d]
    return argv + [SRC]


def _gitleaks_mode(inv) -> str:
    # Only a project that owns a .git directory has history to scan inside the container; a
    # subfolder of a repo (or a worktree whose .git is a file) gets the working tree only.
    return "git" if (Path(inv.get("project", "")) / ".git").is_dir() else "dir"


def _gitleaks_argv(inv):
    return ["gitleaks", _gitleaks_mode(inv), "--redact", "--no-banner", "--report-format", "json",
            "--report-path", OUT + "/gitleaks.json", "--exit-code", "2",
            "--config", OUT + "/gitleaks.toml", "--max-target-megabytes", "5", SRC]


def _gitleaks_prepare(out: Path) -> None:
    paths = ", ".join("'''(^|/)%s/'''" % re.escape(d) for d in _EXCLUDED if d != ".git")
    (out / "gitleaks.toml").write_text(
        "[extend]\nuseDefault = true\n\n[[allowlists]]\ndescription = \"host environments and outputs\"\n"
        "paths = [%s]\n" % paths, encoding="utf-8")


def _checkov_argv(inv):
    argv = ["checkov", "-d", SRC, "--output", "json", "--quiet", "--skip-framework", "secrets"]
    for d in _EXCLUDED:
        argv += ["--skip-path", "/%s(/|$)" % re.escape(d)]
    return argv


def _hadolint_argv(inv):
    return ["hadolint", "--format", "json"] + ["%s/%s" % (SRC, d) for d in inv.get("dockerfiles", [])]


def _zizmor_argv(inv):
    # Explicit files: zizmor's directory collection honours .gitignore and drops tracked
    # workflows under an ignored .github/.
    return ["zizmor", "--format", "json"] + ["%s/%s" % (SRC, f) for f in _workflow_files(inv)]


def _workflow_files(inv):
    wf = Path(inv.get("project", "")) / ".github" / "workflows"
    if not wf.is_dir():
        return []
    return sorted(".github/workflows/%s" % p.name for p in wf.iterdir()
                  if p.is_file() and p.suffix in (".yml", ".yaml"))


def _actionlint_argv(inv):
    return ["actionlint", "-format", "{{json .}}"] + ["%s/%s" % (SRC, f) for f in _workflow_files(inv)]


def _lizard_argv(inv):
    argv = ["lizard", "--csv", "-i", "1000000"]
    for d in _EXCLUDED:
        argv += ["-x", "*/%s/*" % d]
    return argv + [SRC]


def _jscpd_argv(inv):
    return ["jscpd", "--reporters", "json", "--output", OUT + "/jscpd", "--silent", "--no-tips",
            "--ignore", ",".join("**/%s/**" % d for d in _EXCLUDED), SRC]


def _ruff_argv(inv):
    argv = ["ruff", "check", "--output-format", "json", "--exit-zero", "--no-cache"]
    for d in _EXCLUDED:
        argv += ["--extend-exclude", "**/%s" % d]
    return argv + [SRC]


def _trivy_argv(inv):
    # Filesystem mode only: no `trivy image`/`repo`, no client/server mode, no token. Secret
    # scanning stays off (Gitleaks is the single, redacted secrets source). A project's own
    # trivy.yaml or .trivyignore (WORKDIR is /src) must not reconfigure or silence the scan.
    argv = ["trivy", "fs", "--format", "json", "--output", OUT + "/trivy.json", "--exit-code", "0",
            "--scanners", "vuln,misconfig,license", "--cache-dir", "/tmp/trivy-cache",
            "--disable-telemetry", "--skip-version-check", "--no-progress",
            "--config", "", "--ignorefile", ""]
    for d in _EXCLUDED:
        # a bare name matches only at the scan root, `**/name` only below it
        argv += ["--skip-dirs", d, "--skip-dirs", "**/" + d]
    return argv + [SRC]


# ---- partial detection ------------------------------------------------------------------------
def _errors_partial(label):
    def check(path: Path):
        errors = json.loads(Path(path).read_text(encoding="utf-8")).get("errors") or []
        return "%d %s error(s) while scanning; results may be incomplete" % (len(errors), label) if errors else None
    return check


_F = frozenset
SCANNERS = [
    ScannerSpec("semgrep", _semgrep_applies, _semgrep_argv, "semgrep.json", _F({0}), _F({1}),
                parsers.parse_semgrep, ["semgrep", "--version"],
                scrub_keys=_F({"metavars", "fix", "fix_regex", "lines"}),
                partial_check=_errors_partial("semgrep")),
    ScannerSpec("bandit", _stack("python"), _bandit_argv, "bandit.json", _F({0}), _F({1}),
                parsers.parse_bandit, ["bandit", "--version"], scrub_keys=_F({"code"}),
                partial_check=_errors_partial("bandit"), na_reason="no Python code in the project"),
    ScannerSpec("osv-scanner", _has_manifest, _osv_argv, "osv.json", _F({0}), _F({1}),
                parsers.parse_osv, ["osv-scanner", "--version"],
                na_reason="no dependency manifest or lockfile"),
    ScannerSpec("gitleaks", _always, _gitleaks_argv, "gitleaks.json", _F({0}), _F({2}),
                parsers.parse_gitleaks, ["gitleaks", "version"], scrub_keys=_F({"Secret", "Match"}),
                notes=lambda inv: {"mode": _gitleaks_mode(inv)}, prepare=_gitleaks_prepare),
    ScannerSpec("checkov", _any("dockerfiles", "compose_files", "iac_files", "github_workflows"),
                _checkov_argv, "checkov.json", _F({0}), _F({1}), parsers.parse_checkov,
                ["checkov", "--version"], capture_stdout=True, scrub_keys=_F({"code_block"}),
                na_reason="no Dockerfile, compose, IaC or workflow files"),
    ScannerSpec("hadolint", _any("dockerfiles"), _hadolint_argv, "hadolint.json", _F({0}), _F({1}),
                parsers.parse_hadolint, ["hadolint", "--version"], capture_stdout=True,
                na_reason="no Dockerfile"),
    ScannerSpec("zizmor", _any("github_workflows"), _zizmor_argv, "zizmor.json", _F({0}),
                _F({11, 12, 13, 14}), parsers.parse_zizmor, ["zizmor", "--version"],
                capture_stdout=True, scrub_keys=_F({"feature", "fixes"}),
                notes=lambda inv: {"mode": ZIZMOR_MODE}, na_reason="no GitHub Actions workflows"),
    ScannerSpec("actionlint", _any("github_workflows"), _actionlint_argv, "actionlint.json", _F({0}),
                _F({1}), parsers.parse_actionlint, ["actionlint", "-version"], capture_stdout=True,
                scrub_keys=_F({"snippet"}), na_reason="no GitHub Actions workflows"),
    ScannerSpec("lizard", _stack("python", "javascript"), _lizard_argv, "lizard.csv", _F({0}), _F(),
                parsers.parse_lizard, ["lizard", "--version"], capture_stdout=True),
    ScannerSpec("jscpd", _stack("python", "javascript"), _jscpd_argv, "jscpd/jscpd-report.json",
                _F({0}), _F(), parsers.parse_jscpd, ["jscpd", "--version"], scrub_keys=_F({"fragment"})),
    ScannerSpec("ruff", _stack("python"), _ruff_argv, "ruff.json", _F({0}), _F(),
                parsers.parse_ruff, ["ruff", "--version"], capture_stdout=True,
                na_reason="no Python code in the project"),
    ScannerSpec("trivy", _trivy_applies, _trivy_argv, "trivy.json", _F({0}), _F(),
                parsers.parse_trivy, ["trivy", "--version"], scrub_keys=_F({"Code"}),
                na_reason="no dependency manifest, lockfile, Dockerfile, compose, IaC or k8s files"),
]


# ---- runner -----------------------------------------------------------------------------------
def classify_exit(spec: ScannerSpec, exit_code, timed_out: bool, output_exists: bool) -> str:
    """Scanner state for one finished run. A clean exit without a report is a failure, not a pass."""
    if timed_out:
        return "failed"
    if exit_code is None:
        return "unavailable"
    if exit_code in spec.ok_codes or exit_code in spec.findings_codes:
        return "completed" if output_exists else "failed"
    return "failed"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tail(text: str) -> str:
    text = " ".join((text or "").split())
    return text[-STDERR_TAIL:]


def _remove(path: Path) -> None:
    if path.is_dir():
        for child in path.iterdir():
            _remove(child)
        path.rmdir()
    elif path.exists():
        path.unlink()


def _scrub(node, keys) -> None:
    if isinstance(node, dict):
        for k in [k for k in node if k in keys]:
            del node[k]
        for v in node.values():
            _scrub(v, keys)
    elif isinstance(node, list):
        for v in node:
            _scrub(v, keys)


def _scrub_file(path: Path, keys) -> None:
    if not keys or path.suffix != ".json":
        return
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return
    _scrub(doc, keys)
    # The report is owned by the container user (often 0644), so replace the file instead of
    # opening it for writing: replacing needs only write access to the directory.
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, str(path))
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _version(paths: AuditPaths, spec: ScannerSpec) -> Optional[str]:
    res = dockerutil.run(dockerutil.scanner_run_argv(paths, spec.version_argv), VERSION_TIMEOUT)
    if res.exit_code != 0:
        return None
    for line in (res.stdout or res.stderr).splitlines():
        if line.strip():
            return line.strip().split(" ")[-1] if " " in line.strip() else line.strip()
    return None


def _run_one(paths: AuditPaths, spec: ScannerSpec, inventory: dict, timeout: int, out: Path) -> RunRecord:
    started = _now()
    target = out / spec.output
    _remove(out / spec.output.split("/")[0])
    stderr_log = out / (spec.name + ".stderr.log")
    _remove(stderr_log)
    if spec.prepare:
        spec.prepare(out)
    tool_argv = spec.argv(inventory)
    argv = dockerutil.scanner_run_argv(paths, tool_argv)
    res = dockerutil.run(argv, timeout)
    if spec.capture_stdout and res.stdout.strip():
        target.write_text(res.stdout, encoding="utf-8")
    output_exists = target.is_file() and target.stat().st_size > 0
    state = classify_exit(spec, res.exit_code, res.timed_out, output_exists)
    reason = None
    counts = dict(spec.notes(inventory)) if spec.notes else {}
    if res.timed_out:
        reason = "timeout after %ds" % timeout
    elif state == "unavailable":
        reason = "could not start docker: %s" % _tail(res.stderr)
    elif state == "failed":
        if res.exit_code in spec.ok_codes | spec.findings_codes:
            reason = "exit code %s but no report was written" % res.exit_code
        else:
            reason = "exit code %s: %s" % (res.exit_code, _tail(res.stderr))
        if re.search(r"permission denied", res.stderr, re.I):
            state = "blocked_by_permissions"
    if state == "completed":
        try:
            _scrub_file(target, spec.scrub_keys)
        except OSError as exc:
            state, reason = "failed", "scrub failed: %s" % exc
    if state == "completed":
        try:
            counts["leads"] = len(spec.parse(target))
            if spec.partial_check:
                reason = spec.partial_check(target)
                if reason:
                    state = "partial"
        except (ValueError, KeyError, TypeError, AttributeError, OSError) as exc:
            state, reason = "failed", "unparseable output: %s" % exc
    if state != "completed" and res.stderr:
        stderr_log.write_text(res.stderr, encoding="utf-8")
    return RunRecord(
        tool=spec.name, version=_version(paths, spec), argv=tool_argv, started_at=started,
        duration_s=round(res.duration_s, 2), exit_code=res.exit_code, status=state,
        raw_output="scanners/%s" % spec.output if output_exists else None, reason=reason, counts=counts)


def clear_outputs(paths: AuditPaths) -> None:
    """Empty raw/scanners/ (kept as a directory) before a full re-scan."""
    out = paths.raw / "scanners"
    if out.is_dir():
        for child in out.iterdir():
            _remove(child)


def run_scanners(paths: AuditPaths, inventory: dict, only: Optional[list] = None,
                 timeout: int = 900, keep: Optional[set] = None) -> list:
    """Run every applicable scanner (or just `only`); append one ledger record per registry entry.

    Tools in `keep` (not selected with --only, but already recorded by an earlier scan) get no new
    record, so their earlier record stays the current one.
    """
    out = dockerutil.ensure_scanner_out(paths)
    records = []
    for spec in SCANNERS:
        if only is not None and spec.name not in only and spec.name in (keep or ()):
            continue
        if only is not None and spec.name not in only:
            rec = RunRecord(spec.name, None, [], _now(), 0.0, None, "not_requested",
                            reason="not selected with --only")
        elif not spec.applies(inventory):
            rec = RunRecord(spec.name, None, [], _now(), 0.0, None, "not_applicable", reason=spec.na_reason)
        else:
            rec = _run_one(paths, spec, inventory, timeout, out)
        append_run(paths.raw, rec)
        records.append(rec)
    return records


def collect_leads(paths: AuditPaths, records: list) -> list:
    """Parse the raw output of every completed or partial run."""
    by_name = {s.name: s for s in SCANNERS}
    leads = []
    for rec in records:
        if rec.status in ("completed", "partial") and rec.raw_output:
            leads += by_name[rec.tool].parse(paths.raw / rec.raw_output)
    return leads
