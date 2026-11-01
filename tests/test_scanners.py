import json
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "software-project-audit" / "scripts"))

from auditlib import dockerutil, scanners  # noqa: E402
from auditlib.discover import EXCLUDED_DIRS  # noqa: E402
from auditlib.ledger import load_runs  # noqa: E402
from auditlib.paths import AuditPaths  # noqa: E402

DATA = Path(__file__).resolve().parent / "data" / "scanner-output"
NAMES = ["semgrep", "bandit", "osv-scanner", "gitleaks", "checkov", "hadolint", "zizmor",
         "actionlint", "lizard", "jscpd", "ruff", "trivy"]


def _inv(project, **kw):
    inv = {"project": str(project), "git": {"is_repo": False}, "stacks": ["python"],
           "packages": [{"path": ".", "ecosystem": "python", "manifest": "requirements.txt"}], "github_workflows": False,
           "dockerfiles": [], "compose_files": [], "iac_files": [], "ci_files": []}
    inv.update(kw)
    return inv


def _spec(name):
    return next(s for s in scanners.SCANNERS if s.name == name)


def test_registry_order():
    assert [s.name for s in scanners.SCANNERS] == NAMES


def test_exit_code_classification():
    semgrep = _spec("semgrep")
    assert scanners.classify_exit(semgrep, 1, False, True) == "completed"
    assert scanners.classify_exit(semgrep, 0, False, True) == "completed"
    assert scanners.classify_exit(semgrep, 2, False, True) == "failed"
    assert scanners.classify_exit(semgrep, None, True, False) == "failed"
    assert scanners.classify_exit(semgrep, 0, False, False) == "failed"
    assert scanners.classify_exit(semgrep, 1, False, False) == "failed"
    assert scanners.classify_exit(semgrep, None, False, False) == "unavailable"
    zizmor = _spec("zizmor")
    assert scanners.classify_exit(zizmor, 14, False, True) == "completed"
    assert scanners.classify_exit(zizmor, 1, False, True) == "failed"
    assert scanners.classify_exit(zizmor, 3, False, True) == "failed"
    gitleaks = _spec("gitleaks")
    assert scanners.classify_exit(gitleaks, 2, False, True) == "completed"
    assert scanners.classify_exit(gitleaks, 1, False, True) == "failed"
    osv = _spec("osv-scanner")
    assert scanners.classify_exit(osv, 1, False, True) == "completed"
    assert scanners.classify_exit(osv, 127, False, True) == "failed"
    assert scanners.classify_exit(osv, 128, False, True) == "failed"
    trivy = _spec("trivy")
    assert scanners.classify_exit(trivy, 0, False, True) == "completed"
    assert scanners.classify_exit(trivy, 1, False, True) == "failed"


def test_ok_and_findings_codes_disjoint_and_documented():
    for s in scanners.SCANNERS:
        assert s.ok_codes and not (s.ok_codes & s.findings_codes), s.name
        assert 0 in s.ok_codes, s.name


def test_gitleaks_argv_uses_dir_mode_without_git(tmp_path):
    spec = _spec("gitleaks")
    argv = spec.argv(_inv(tmp_path))
    assert argv[0] == "gitleaks" and argv[1] == "dir"
    assert "--redact" in argv and "git" not in argv[:2]


def test_gitleaks_argv_uses_git_mode_with_dot_git(tmp_path):
    (tmp_path / ".git").mkdir()
    argv = _spec("gitleaks").argv(_inv(tmp_path, git={"is_repo": True}))
    assert argv[:2] == ["gitleaks", "git"] and "--redact" in argv


def test_gitleaks_subfolder_of_repo_uses_dir_mode(tmp_path):
    sub = tmp_path / "pkg"
    sub.mkdir()
    (tmp_path / ".git").mkdir()
    argv = _spec("gitleaks").argv(_inv(sub, git={"is_repo": True}))
    assert argv[1] == "dir"


def test_semgrep_argv(tmp_path):
    argv = _spec("semgrep").argv(_inv(tmp_path))
    assert "--metrics=off" in argv
    for pack in dockerutil.load_versions()["semgrep_packs"]:
        assert "/rules/%s.yml" % pack.replace("/", "-") in argv
    assert argv.count("--config") == len(dockerutil.load_versions()["semgrep_packs"])
    for d in EXCLUDED_DIRS:
        assert d in argv
    assert argv[-1] == "/src"


def test_zizmor_argv_lists_workflow_files(tmp_path):
    # zizmor's directory collection honours .gitignore, so a tracked workflow under an
    # ignored .github/ (seen in the quill-dc-backend pilot) is dropped and zizmor exits 3.
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "deploy.yml").write_text("on: push\n")
    (tmp_path / ".gitignore").write_text(".github/*\n")
    argv = _spec("zizmor").argv(_inv(tmp_path, github_workflows=True))
    assert argv[-1] == "/src/.github/workflows/deploy.yml"
    assert "/src" not in argv


def test_network_flags_not_restricted(tmp_path):
    inv = _inv(tmp_path, github_workflows=True, dockerfiles=["Dockerfile"])
    for s in scanners.SCANNERS:
        argv = s.argv(inv)
        assert "--skip-download" not in argv and "--offline" not in argv, s.name


def test_secrets_framework_skipped_for_checkov(tmp_path):
    argv = _spec("checkov").argv(_inv(tmp_path, dockerfiles=["Dockerfile"]))
    assert "--skip-framework" in argv and "secrets" in argv


def test_applies(tmp_path):
    js = _inv(tmp_path, stacks=["javascript"], packages=[{"path": ".", "ecosystem": "javascript", "manifest": "package.json"}])
    assert not _spec("bandit").applies(js) and not _spec("ruff").applies(js)
    assert _spec("semgrep").applies(js) and _spec("osv-scanner").applies(js) and _spec("jscpd").applies(js)
    assert not _spec("hadolint").applies(js) and not _spec("zizmor").applies(js)
    assert _spec("gitleaks").applies(js)
    full = _inv(tmp_path, github_workflows=True, dockerfiles=["Dockerfile"])
    assert all(_spec(n).applies(full) for n in NAMES)
    empty = _inv(tmp_path, stacks=[], packages=[])
    assert not _spec("semgrep").applies(empty) and not _spec("osv-scanner").applies(empty)
    assert _spec("gitleaks").applies(empty)


class FakeDocker:
    """Replaces dockerutil.run; scripted per tool name."""

    def __init__(self, paths, script=None):
        self.paths = paths
        self.script = script or {}
        self.calls = []

    def __call__(self, argv, timeout, input_bytes=None):
        self.calls.append(argv)
        tool_argv = argv[argv.index(dockerutil.SCANNER_IMAGE) + 1:]
        tool = tool_argv[0]
        if tool_argv[-1] in ("--version", "-version", "version") or "--version" in tool_argv[:2]:
            return dockerutil.CompletedRun(0, "%s 9.9.9\nextra line\n" % tool, "", False, 0.01)
        handler = self.script.get(tool)
        if handler is None:
            return dockerutil.CompletedRun(0, "", "", False, 0.01)
        return handler(self, tool_argv, timeout)


def _install(monkeypatch, paths, script=None):
    fake = FakeDocker(paths, script)
    monkeypatch.setattr(scanners.dockerutil, "run", fake)
    return fake


def _audit_paths(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    return AuditPaths.for_project(project)


def test_not_applicable_recorded(tmp_path, monkeypatch):
    paths = _audit_paths(tmp_path)
    _install(monkeypatch, paths)
    inv = _inv(paths.project, stacks=["javascript"], packages=[{"path": ".", "ecosystem": "javascript", "manifest": "package.json"}])
    records = scanners.run_scanners(paths, inv)
    assert [r.tool for r in records] == NAMES
    bandit = next(r for r in records if r.tool == "bandit")
    assert bandit.status == "not_applicable" and bandit.reason
    assert [r.tool for r in load_runs(paths.raw)] == NAMES
    assert (paths.raw / "scanners").is_dir()


def test_only_marks_others_not_requested(tmp_path, monkeypatch):
    paths = _audit_paths(tmp_path)
    _install(monkeypatch, paths)
    records = scanners.run_scanners(paths, _inv(paths.project), only=["ruff"])
    states = {r.tool: r.status for r in records}
    assert states["ruff"] != "not_requested"
    assert all(v == "not_requested" for k, v in states.items() if k != "ruff")
    assert len(records) == len(NAMES)


def test_timeout_is_failed_with_reason(tmp_path, monkeypatch):
    paths = _audit_paths(tmp_path)

    def timeout(fake, argv, t):
        return dockerutil.CompletedRun(None, "", "partial stderr", True, float(t))

    _install(monkeypatch, paths, {"bandit": timeout})
    rec = next(r for r in scanners.run_scanners(paths, _inv(paths.project), only=["bandit"], timeout=7)
               if r.tool == "bandit")
    assert rec.status == "failed" and "timeout" in rec.reason and "7" in rec.reason
    assert (paths.raw / "scanners" / "bandit.stderr.log").read_text() == "partial stderr"


def test_crash_keeps_stderr_and_is_failed(tmp_path, monkeypatch):
    paths = _audit_paths(tmp_path)

    def crash(fake, argv, t):
        return dockerutil.CompletedRun(2, "", "Traceback: boom", False, 0.2)

    _install(monkeypatch, paths, {"semgrep": crash})
    rec = next(r for r in scanners.run_scanners(paths, _inv(paths.project), only=["semgrep"])
               if r.tool == "semgrep")
    assert rec.status == "failed" and rec.exit_code == 2
    assert "boom" in (paths.raw / "scanners" / "semgrep.stderr.log").read_text()
    assert rec.version == "9.9.9"


def test_permission_denied_is_blocked(tmp_path, monkeypatch):
    paths = _audit_paths(tmp_path)

    def denied(fake, argv, t):
        return dockerutil.CompletedRun(1, "", "open /out/bandit.json: permission denied", False, 0.2)

    _install(monkeypatch, paths, {"bandit": denied})
    rec = next(r for r in scanners.run_scanners(paths, _inv(paths.project), only=["bandit"])
               if r.tool == "bandit")
    assert rec.status == "blocked_by_permissions"


def test_findings_exit_with_output_is_completed_and_leads_collected(tmp_path, monkeypatch):
    paths = _audit_paths(tmp_path)

    def bandit(fake, argv, t):
        shutil.copy(DATA / "bandit.json", fake.paths.raw / "scanners" / "bandit.json")
        return dockerutil.CompletedRun(1, "", "", False, 0.3)

    _install(monkeypatch, paths, {"bandit": bandit})
    records = scanners.run_scanners(paths, _inv(paths.project), only=["bandit"])
    rec = next(r for r in records if r.tool == "bandit")
    assert rec.status == "completed" and rec.counts["leads"] == 3
    assert rec.raw_output == "scanners/bandit.json"
    leads = scanners.collect_leads(paths, records)
    assert len(leads) == 3 and {lead.tool for lead in leads} == {"bandit"}


def test_bandit_code_snippets_scrubbed(tmp_path, monkeypatch):
    paths = _audit_paths(tmp_path)
    doc = json.loads((DATA / "bandit.json").read_text())
    doc["results"][0]["code"] = "password = 'hunter2hunter2'"

    def bandit(fake, argv, t):
        (fake.paths.raw / "scanners" / "bandit.json").write_text(json.dumps(doc))
        return dockerutil.CompletedRun(1, "", "", False, 0.3)

    _install(monkeypatch, paths, {"bandit": bandit})
    scanners.run_scanners(paths, _inv(paths.project), only=["bandit"])
    assert "hunter2" not in (paths.raw / "scanners" / "bandit.json").read_text()


def test_unparseable_output_is_failed(tmp_path, monkeypatch):
    paths = _audit_paths(tmp_path)

    def bandit(fake, argv, t):
        (fake.paths.raw / "scanners" / "bandit.json").write_text("{not json")
        return dockerutil.CompletedRun(1, "", "", False, 0.3)

    _install(monkeypatch, paths, {"bandit": bandit})
    rec = next(r for r in scanners.run_scanners(paths, _inv(paths.project), only=["bandit"])
               if r.tool == "bandit")
    assert rec.status == "failed" and "unparseable" in rec.reason


def test_semgrep_errors_make_partial(tmp_path, monkeypatch):
    paths = _audit_paths(tmp_path)
    doc = json.loads((DATA / "semgrep.json").read_text())
    doc["errors"] = [{"type": "PartialParsing", "level": "warn"}]

    def semgrep(fake, argv, t):
        (fake.paths.raw / "scanners" / "semgrep.json").write_text(json.dumps(doc))
        return dockerutil.CompletedRun(0, "", "", False, 0.3)

    _install(monkeypatch, paths, {"semgrep": semgrep})
    rec = next(r for r in scanners.run_scanners(paths, _inv(paths.project), only=["semgrep"])
               if r.tool == "semgrep")
    assert rec.status == "partial" and "1" in rec.reason


def test_stdout_captured_to_output_file(tmp_path, monkeypatch):
    paths = _audit_paths(tmp_path)
    text = (DATA / "ruff.json").read_text()

    def ruff(fake, argv, t):
        return dockerutil.CompletedRun(0, text, "", False, 0.3)

    _install(monkeypatch, paths, {"ruff": ruff})
    records = scanners.run_scanners(paths, _inv(paths.project), only=["ruff"])
    rec = next(r for r in records if r.tool == "ruff")
    assert rec.status == "completed" and rec.counts["leads"] == 1
    assert (paths.raw / "scanners" / "ruff.json").read_text() == text


def test_modes_recorded(tmp_path, monkeypatch):
    paths = _audit_paths(tmp_path)
    _install(monkeypatch, paths)
    inv = _inv(paths.project, github_workflows=True)
    records = {r.tool: r for r in scanners.run_scanners(paths, inv)}
    assert records["gitleaks"].counts["mode"] == "dir"
    assert records["zizmor"].counts["mode"] == "offline (no GitHub token; online audits skipped)"


def test_scanners_called_through_scanner_run_argv(tmp_path, monkeypatch):
    paths = _audit_paths(tmp_path)
    fake = _install(monkeypatch, paths)
    scanners.run_scanners(paths, _inv(paths.project), only=["ruff"])
    assert fake.calls
    for argv in fake.calls:
        assert argv[:2] == ["docker", "run"] and "--network" in argv and "bridge" in argv
        assert "%s:/src:ro" % paths.project in argv


def test_scan_cli_rejects_missing_project(tmp_path):
    import audit

    paths = _audit_paths(tmp_path)
    assert audit.main(["scan", "--project", str(paths.project / "nope")]) == 2


def _scan_cli(monkeypatch, paths, script=None):
    """Run the scan CLI with a fake image build and fake scanner containers."""
    import audit

    monkeypatch.setattr(dockerutil, "build_scanner_image",
                        lambda force=False: dockerutil.CompletedRun(0, "", "", False, 0.0))
    _install(monkeypatch, paths, script)
    paths.raw.mkdir(parents=True, exist_ok=True)
    (paths.raw / "inventory.json").write_text(json.dumps(_inv(paths.project)))
    return lambda *extra: audit.main(["scan", "--project", str(paths.project), *extra])


def _ruff_out(fake, argv, t):
    return dockerutil.CompletedRun(0, (DATA / "ruff.json").read_text(), "", False, 0.3)


def _bandit_out(fake, argv, t):
    shutil.copy(DATA / "bandit.json", fake.paths.raw / "scanners" / "bandit.json")
    return dockerutil.CompletedRun(1, "", "", False, 0.3)


def _test_rec():
    from auditlib.models import RunRecord
    return RunRecord("tests:.", "python:3.12-slim", ["sh", "-lc", "pytest"], "2026-01-01T00:00:00Z", 5.0, 0,
                     "completed", "audit/raw/tests/root", None, {"passed": 1})


def _lead_tools(paths):
    return {t for lead in json.loads((paths.raw / "leads.json").read_text()) for t in lead["tools"]}


def test_scan_rerun_replaces_scanner_records_and_keeps_test_records(tmp_path, monkeypatch):
    from auditlib.ledger import append_run

    paths = _audit_paths(tmp_path)
    scan = _scan_cli(monkeypatch, paths, {"ruff": _ruff_out})
    append_run(paths.raw, _test_rec())  # test ran before scan
    assert scan() == 0
    (paths.raw / "scanners" / "stale.json").write_text("{}")
    assert scan() == 0
    tools = [r.tool for r in load_runs(paths.raw)]
    assert tools.count("tests:.") == 1
    assert sorted(t for t in tools if t != "tests:.") == sorted(NAMES)
    assert not (paths.raw / "scanners" / "stale.json").exists()
    assert "ruff" in _lead_tools(paths)


def test_scan_only_replaces_just_those_tools(tmp_path, monkeypatch):
    from auditlib.ledger import append_run

    paths = _audit_paths(tmp_path)
    scan = _scan_cli(monkeypatch, paths, {"ruff": _ruff_out})
    assert scan() == 0
    append_run(paths.raw, _test_rec())
    first = {r.tool: r for r in load_runs(paths.raw)}
    _install(monkeypatch, paths, {"bandit": _bandit_out})
    assert scan("--only", "bandit") == 0
    runs = load_runs(paths.raw)
    by_tool = {r.tool: r for r in runs}
    assert len(runs) == len(NAMES) + 1 and set(by_tool) == set(NAMES) | {"tests:."}
    for tool in NAMES:
        if tool != "bandit":
            assert by_tool[tool] == first[tool], tool  # untouched, not turned into not_requested
    assert by_tool["bandit"].status == "completed" and by_tool["bandit"] != first["bandit"]
    assert by_tool["tests:."] == first["tests:."]
    assert {"ruff", "bandit"} <= _lead_tools(paths)  # leads re-deduplicated from every raw output present


def test_scan_only_on_fresh_audit_marks_others_not_requested(tmp_path, monkeypatch):
    paths = _audit_paths(tmp_path)
    scan = _scan_cli(monkeypatch, paths, {"ruff": _ruff_out})
    assert scan("--only", "ruff") == 0
    states = {r.tool: r.status for r in load_runs(paths.raw)}
    assert states["ruff"] == "completed"
    assert all(v == "not_requested" for k, v in states.items() if k != "ruff")


def test_scan_reruns_cleanly_after_interrupted_run(tmp_path, monkeypatch):
    from auditlib.ledger import append_run
    from auditlib.models import RunRecord

    paths = _audit_paths(tmp_path)
    scan = _scan_cli(monkeypatch, paths)
    for tool in ("semgrep", "bandit", "semgrep"):  # a killed run left partial (even duplicated) records
        append_run(paths.raw, RunRecord(tool, None, [], "2026-01-01T00:00:00Z", 0.0, None, "failed", reason="x"))
    (paths.raw / "scanners" / "semgrep.json").parent.mkdir(parents=True, exist_ok=True)
    (paths.raw / "scanners" / "semgrep.json").write_text("{truncated")
    assert scan() == 0
    tools = [r.tool for r in load_runs(paths.raw)]
    assert sorted(tools) == sorted(NAMES)
    assert not (paths.raw / "scanners" / "semgrep.json").exists()


def test_scan_cli_resolves_relative_project(tmp_path, monkeypatch):
    import audit

    seen = {}

    def fake_run(paths, inventory, only=None, timeout=900, **kw):
        seen["project"] = paths.project
        return []

    proj = tmp_path / "proj"
    proj.mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(scanners, "run_scanners", fake_run)
    monkeypatch.setattr(dockerutil, "build_scanner_image",
                        lambda force=False: dockerutil.CompletedRun(0, "", "", False, 0.0))
    assert audit.main(["scan", "--project", "proj"]) == 0
    assert seen["project"].is_absolute() and seen["project"] == proj.resolve()


def test_scrub_succeeds_on_read_only_report(tmp_path, monkeypatch):
    paths = _audit_paths(tmp_path)
    doc = json.loads((DATA / "bandit.json").read_text())
    doc["results"][0]["code"] = "password = 'hunter2hunter2'"

    def bandit(fake, argv, t):
        f = fake.paths.raw / "scanners" / "bandit.json"
        f.write_text(json.dumps(doc))
        f.chmod(0o444)  # as a container-owned 0644 file would be for us
        return dockerutil.CompletedRun(1, "", "", False, 0.3)

    _install(monkeypatch, paths, {"bandit": bandit})
    rec = next(r for r in scanners.run_scanners(paths, _inv(paths.project), only=["bandit"])
               if r.tool == "bandit")
    assert rec.status == "completed", rec.reason
    assert "hunter2" not in (paths.raw / "scanners" / "bandit.json").read_text()
    assert not list((paths.raw / "scanners").glob("*.tmp"))


def test_scrub_failure_has_distinct_reason(tmp_path, monkeypatch):
    paths = _audit_paths(tmp_path)

    def bandit(fake, argv, t):
        shutil.copy(DATA / "bandit.json", fake.paths.raw / "scanners" / "bandit.json")
        return dockerutil.CompletedRun(1, "", "", False, 0.3)

    def boom(*a, **k):
        raise PermissionError("nope")

    _install(monkeypatch, paths, {"bandit": bandit})
    monkeypatch.setattr(scanners.os, "replace", boom)
    rec = next(r for r in scanners.run_scanners(paths, _inv(paths.project), only=["bandit"])
               if r.tool == "bandit")
    assert rec.status == "failed" and rec.reason.startswith("scrub failed")


def test_osv_needs_manifest_or_lockfile(tmp_path):
    only_py = _inv(tmp_path, packages=[])
    assert not _spec("osv-scanner").applies(only_py)
    assert not _spec("osv-scanner").applies(_inv(tmp_path, packages=[{"path": ".", "manifest": None, "lockfile": None}]))
    assert _spec("osv-scanner").applies(_inv(tmp_path, packages=[{"path": ".", "manifest": "requirements.txt"}]))
    assert _spec("osv-scanner").applies(_inv(tmp_path, packages=[{"path": ".", "lockfile": "uv.lock"}]))


def test_trivy_spec_applies_and_argv(tmp_path):
    spec = _spec("trivy")
    assert spec.applies(_inv(tmp_path))
    assert spec.applies(_inv(tmp_path, packages=[{"path": ".", "lockfile": "uv.lock"}]))
    bare = _inv(tmp_path, stacks=["python"], packages=[])
    assert not spec.applies(bare)
    for key, value in (("dockerfiles", ["Dockerfile"]), ("compose_files", ["compose.yaml"]),
                       ("iac_files", ["main.tf"]), ("k8s_files", ["k8s/deploy.yaml"])):
        assert spec.applies(_inv(tmp_path, packages=[], **{key: value})), key
    argv = spec.argv(_inv(tmp_path))
    assert argv[:2] == ["trivy", "fs"] and argv[-1] == "/src"
    flags = dict(zip(argv, argv[1:]))
    assert flags["--format"] == "json" and flags["--output"] == "/out/trivy.json"
    assert flags["--exit-code"] == "0" and flags["--cache-dir"] == "/tmp/trivy-cache"
    assert flags["--scanners"] == "vuln,misconfig,license"
    assert "secret" not in flags["--scanners"]
    # project-supplied trivy.yaml / .trivyignore must not reconfigure or silence the scan
    assert flags["--config"] == "" and flags["--ignorefile"] == ""
    assert "--disable-telemetry" in argv and "--skip-version-check" in argv
    assert "--quiet" not in argv and "-q" not in argv  # a crashed run's log must reach stderr
    skipped = [argv[i + 1] for i, a in enumerate(argv) if a == "--skip-dirs"]
    for d in EXCLUDED_DIRS:
        assert d in skipped and "**/" + d in skipped, d
    for banned in ("--server", "--token", "--token-header", "--registry-token", "image", "repo",
                   "--db-repository", "--checks-bundle-repository"):
        assert banned not in argv, banned
    assert spec.output == "trivy.json" and spec.ok_codes == frozenset({0}) and not spec.findings_codes


def test_trivy_scrubs_misconfig_code_lines(tmp_path, monkeypatch):
    paths = _audit_paths(tmp_path)
    doc = json.loads((DATA / "trivy.json").read_text())
    mis = doc["Results"][1]["Misconfigurations"][0]
    mis["CauseMetadata"]["Code"] = {"Lines": [{"Number": 1, "Content": "FROM python:3.12 # hunter2hunter2"}]}

    def trivy(fake, argv, t):
        (fake.paths.raw / "scanners" / "trivy.json").write_text(json.dumps(doc))
        return dockerutil.CompletedRun(0, "", "", False, 0.3)

    _install(monkeypatch, paths, {"trivy": trivy})
    (rec,) = [r for r in scanners.run_scanners(paths, _inv(paths.project), only=["trivy"]) if r.tool == "trivy"]
    assert rec.status == "completed" and rec.counts["leads"] == 9
    assert "hunter2hunter2" not in (paths.raw / "scanners" / "trivy.json").read_text()
