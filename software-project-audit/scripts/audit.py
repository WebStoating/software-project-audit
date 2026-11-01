#!/usr/bin/env python3
"""software-project-audit CLI."""
import argparse
import json
import shutil
import signal
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

SUBCOMMANDS = ["readiness", "discover", "scan", "test", "validate", "render"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="audit.py", description="Software project audit orchestrator.")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in SUBCOMMANDS:
        p = sub.add_parser(name, help=f"{name} step of the audit")
        p.add_argument("--project", type=Path, default=Path.cwd(), help="project to audit (default: cwd)")
        if name == "scan":
            p.add_argument("--only", default=None, help="comma-separated scanners to run; the rest are recorded as not_requested")
            p.add_argument("--timeout", type=int, default=900, help="per-scanner timeout in seconds (default: 900)")
        if name == "test":
            p.add_argument("--command", dest="overrides", action="append", default=[], metavar="PATH=CMD",
                           help="test command for the package at PATH, replacing the planned one (repeatable)")
            p.add_argument("--python", dest="pythons", action="append", default=[], metavar="PATH=INTERPRETER",
                           help="interpreter for the Python package at PATH (repeatable)")
            p.add_argument("--run", action="store_true",
                           help="execute the plan the developer confirmed (without it, only preview)")
        if name == "readiness":
            p.add_argument("--json", action="store_true", help="print JSON instead of a table")
            p.add_argument("--docker", default="docker", help="docker executable (default: docker)")
            p.add_argument("--probe-url", default=None, help="network probe URL (default: OSV API)")
    return parser


def _cleanup_leftovers(project: Path) -> None:
    """Remove temporary coverage tools an interrupted `test --run` left in the project."""
    from auditlib import covtools

    for line in covtools.cleanup_leftovers(project.resolve()):
        print(line)


def cmd_discover(project: Path) -> int:
    from auditlib import discover
    from auditlib.paths import AuditPaths

    if not project.is_dir():
        print("discover: not a directory: %s" % project, file=sys.stderr)
        return 2
    _cleanup_leftovers(project)  # before rotation moves their records into history/
    paths = AuditPaths.for_project(project)
    moved = paths.rotate()
    inventory = discover.discover(project)
    (paths.raw / "inventory.json").write_text(
        json.dumps(inventory, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if moved:
        print("Previous audit moved to %s" % moved)
    print(discover.summary(inventory))
    print("Wrote %s" % (paths.raw / "inventory.json"))
    return 0


def cmd_scan(args) -> int:
    from auditlib import dedupe, dockerutil, discover, scanners
    from auditlib.ledger import load_runs, replace_runs
    from auditlib.paths import AuditPaths

    project = args.project.resolve()  # docker -v needs an absolute path
    if not project.is_dir():
        print("scan: not a directory: %s" % project, file=sys.stderr)
        return 2
    paths = AuditPaths.for_project(project)
    only = [t.strip() for t in args.only.split(",") if t.strip()] if args.only else None
    unknown = sorted(set(only or []) - {s.name for s in scanners.SCANNERS})
    if unknown:
        print("scan: unknown scanner(s): %s" % ", ".join(unknown), file=sys.stderr)
        return 2
    inv_path = paths.raw / "inventory.json"
    if inv_path.is_file():
        inventory = json.loads(inv_path.read_text(encoding="utf-8"))
    else:
        paths.raw.mkdir(parents=True, exist_ok=True)
        inventory = discover.discover(project)
        inv_path.write_text(json.dumps(inventory, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    built = dockerutil.build_scanner_image()
    if built.exit_code != 0:
        print("scan: scanner image is unavailable: %s" % built.stderr.strip()[-500:], file=sys.stderr)
        return 2
    # Re-runnable: replace earlier scanner records and outputs; test records (tests:*) are never touched.
    names = {s.name for s in scanners.SCANNERS}
    if only is None:
        replace_runs(paths.raw, keep=lambda r: r["tool"] not in names)
        scanners.clear_outputs(paths)
        if (paths.raw / "leads.json").exists():
            (paths.raw / "leads.json").unlink()
        keep = set()
    else:
        replace_runs(paths.raw, keep=lambda r: r["tool"] not in only)
        keep = {r.tool for r in load_runs(paths.raw) if r.tool in names}
    scanners.run_scanners(paths, inventory, only=only, timeout=args.timeout, keep=keep)
    records = [r for r in load_runs(paths.raw) if r.tool in names]
    leads = dedupe.dedupe(scanners.collect_leads(paths, records))
    (paths.raw / "leads.json").write_text(json.dumps(leads, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("%-12s %-22s %6s  %s" % ("tool", "state", "leads", "note"))
    for r in records:
        note = r.reason or ", ".join("%s=%s" % kv for kv in r.counts.items() if kv[0] != "leads")
        print("%-12s %-22s %6s  %s" % (r.tool, r.status, r.counts.get("leads", "-"), note))
    bad = [r.tool for r in records if r.status in ("failed", "unavailable", "blocked_by_permissions", "partial")]
    if bad:
        print("WARNING: no usable (or incomplete) results from: %s. This is not a clean result; "
              "see raw/scanners/*.stderr.log." % ", ".join(bad))
    print("%d leads (deduplicated) written to %s" % (len(leads), paths.raw / "leads.json"))
    return 0


def _interrupt(signum, frame):
    raise KeyboardInterrupt


def _pairs(items: list, flag: str) -> "dict | None":
    out = {}
    for item in items:
        pkg_path, sep, value = item.partition("=")
        if not sep or not pkg_path or not value.strip():
            print("test: %s expects PATH=VALUE, got %r" % (flag, item), file=sys.stderr)
            return None
        out[pkg_path] = value
    return out


def _print_plan(plans, skipped, stripped, project: Path, home: str) -> None:
    import shlex

    from auditlib.hostenv import redact

    for plan in plans:
        print("package %s" % plan.package_path)
        print("  cwd: %s" % redact(plan.cwd, project, home))
        print("  command: %s" % redact(shlex.join(plan.argv), project, home))
        for tool in plan.temp_tools:
            print("  temporary coverage tool (removed after the run): %s -> %s" % (
                " ".join("%s==%s" % kv for kv in tool["packages"].items()),
                redact(tool["link"] or tool["target"], project, home)))
    for s in skipped:
        print("skipped %s: %s" % (s["package_path"], s["reason"]))
    if stripped:
        print("credentials removed from the test environment: %s" % ", ".join(stripped))


def _test_run_consent(paths) -> bool:
    """True only when context.json records the developer's explicit yes to running the project's tests."""
    try:
        ctx = json.loads((paths.raw / "context.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(ctx, dict) and ctx.get("test_run_consent") is True


def cmd_test(args) -> int:
    import os
    from dataclasses import asdict
    from datetime import datetime, timezone

    from auditlib import discover, dockerutil, testplan, testrun
    from auditlib.hostenv import build_env, redact
    from auditlib.ledger import append_run, replace_runs
    from auditlib.models import RunRecord
    from auditlib.paths import AuditPaths

    project = args.project.resolve()
    if not project.is_dir():
        print("test: not a directory: %s" % project, file=sys.stderr)
        return 2
    paths = AuditPaths.for_project(project)
    results_path, plan_path = paths.raw / "test-results.json", paths.raw / "test-plan.json"
    overrides, pythons = _pairs(args.overrides, "--command"), _pairs(args.pythons, "--python")
    if overrides is None or pythons is None:
        return 2
    _cleanup_leftovers(project)
    # Running tests executes project code: never without the developer's recorded yes.
    if not _test_run_consent(paths):
        print("test: audit/raw/context.json does not record test_run_consent: true, so the developer has not "
              "agreed to run the project's tests. Skip the test step; no project code may run.", file=sys.stderr)
        return 2
    inv_path = paths.raw / "inventory.json"
    if inv_path.is_file():
        inventory = json.loads(inv_path.read_text(encoding="utf-8"))
    else:
        paths.raw.mkdir(parents=True, exist_ok=True)
        inventory = discover.discover(project)
        inv_path.write_text(json.dumps(inventory, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    unknown = sorted((set(overrides) | set(pythons)) - {p["path"] for p in inventory["packages"]})
    if unknown:
        print("test: --command/--python for unknown package path(s): %s" % ", ".join(unknown), file=sys.stderr)
        return 2
    try:
        plans, skipped = testplan.plan_tests(inventory, project, dockerutil.load_versions(), os.environ,
                                             paths.raw / "tests", overrides, pythons)
    except ValueError as exc:
        print("test: %s" % exc, file=sys.stderr)
        return 2
    home = os.path.expanduser("~")
    digest = testplan.plan_digest(plans, skipped)
    stripped = build_env(os.environ, [], {})[1]

    if not args.run:
        paths.raw.mkdir(parents=True, exist_ok=True)
        plan_path.write_text(json.dumps(
            {"digest": digest, "plans": [p.to_json(project, home) for p in plans], "skipped": skipped,
             "stripped_env": stripped}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        _print_plan(plans, skipped, stripped, project, home)
        print("Nothing was run. These commands run on this machine with the developer's account. "
              "Show this plan to the developer and, once they confirm, rerun with the same options plus --run.")
        print("Wrote %s" % plan_path)
        return 0

    try:
        saved = json.loads(plan_path.read_text(encoding="utf-8"))["digest"]
    except (OSError, ValueError, KeyError, TypeError):
        print("test: no confirmed plan; run `test` without --run first and show the plan to the developer",
              file=sys.stderr)
        return 2
    if saved != digest:
        print("test: the plan changed since the developer confirmed it; run `test` without --run again",
              file=sys.stderr)
        return 2
    # Re-runnable: replace the previous test run (outputs, results, tests:* ledger records) as a whole.
    # Cleared once here, not per package, so testrun's "out_dir already exists" guard still catches
    # two packages of this run colliding on one slug. Scanner records are never touched.
    if (paths.raw / "tests").exists():
        shutil.rmtree(paths.raw / "tests")
    if results_path.exists():
        results_path.unlink()
    replace_runs(paths.raw, keep=lambda r: not r["tool"].startswith("tests:"))
    results = []
    # An agent's command timeout usually sends SIGTERM; turn it into an exception so run_test_plan's
    # finally blocks still kill the test process group and remove temporary coverage tools.
    previous = {sig: signal.signal(sig, _interrupt) for sig in (signal.SIGTERM, signal.SIGHUP)}
    try:
        for plan in plans:
            started = datetime.now(timezone.utc)
            res = testrun.run_test_plan(plan, paths, os.environ)
            res.notes = [redact(n, project, home) for n in res.notes]  # no host paths in results or ledger
            results.append(res)
            append_run(paths.raw, RunRecord(
                tool="tests:%s" % plan.package_path, version=res.runtime_version,
                argv=[redact(a, project, home) for a in plan.argv],
                started_at=started.strftime("%Y-%m-%dT%H:%M:%SZ"),
                duration_s=round((datetime.now(timezone.utc) - started).total_seconds(), 2),
                exit_code=res.exit_codes.get("test"), status=res.status, raw_output=res.raw_dir,
                reason="; ".join(res.notes) or None, counts=dict(res.counts or {})))
    except KeyboardInterrupt:
        print("test: interrupted; test processes were stopped and temporary coverage tools removed. "
              "Rerun the same command to test again.", file=sys.stderr)
        return 2
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    paths.raw.mkdir(parents=True, exist_ok=True)
    results_path.write_text(json.dumps(
        {"plans": [p.to_json(project, home) for p in plans], "skipped": skipped,
         "results": [asdict(r) for r in results]}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("%-24s %-18s %-10s %-14s %s" % ("package", "runtime", "status", "tests", "line coverage"))
    for r in results:
        c = r.counts
        tests = "-" if c is None else "%d/%d/%d/%d" % (c["passed"], c["failed"], c["errors"], c["skipped"])
        cov = "-" if r.coverage is None else "%.1f%%" % r.coverage["line_pct"]
        print("%-24s %-18s %-10s %-14s %s" % (r.package_path, r.runtime_version or "-", r.status, tests, cov))
    for s in skipped:
        print("skipped %s: %s" % (s["package_path"], s["reason"]))
    if results:
        print("tests = passed/failed/errors/skipped")
    for r in results:
        for note in r.notes:
            if note.startswith(("WARNING", "tests modified the working tree")):
                print("WARNING: %s: %s" % (r.package_path, note[len("WARNING: "):] if note.startswith("WARNING")
                                           else note))
        if r.coverage_tool_suggestion:
            print("Suggest to the developer (%s): %s" % (r.package_path, r.coverage_tool_suggestion))
    bad = [r.package_path for r in results if r.status != "completed"]
    if bad:
        print("WARNING: incomplete test results for: %s. See raw/tests/*/test.log." % ", ".join(bad))
    print("Wrote %s" % results_path)
    return 0


def cmd_readiness(args) -> int:
    from auditlib import readiness

    if not args.project.is_dir():
        print("readiness: not a directory: %s" % args.project, file=sys.stderr)
        return 2
    kwargs = {"docker": args.docker}
    if args.probe_url:
        kwargs["probe_url"] = args.probe_url
    result = readiness.check_readiness(args.project, **kwargs)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(readiness.format_table(result))
    return 0 if result["ready"] else 2


def cmd_validate(project: Path) -> int:
    from auditlib.paths import AuditPaths
    from auditlib.validate import validate_audit

    if not project.is_dir():
        print("validate: not a directory: %s" % project, file=sys.stderr)
        return 2
    errors = validate_audit(AuditPaths.for_project(project))
    if errors:
        print("\n".join(errors))
        return 1
    print("OK")
    return 0


def cmd_render(project: Path) -> int:
    from auditlib.paths import AuditPaths
    from auditlib.render import render_all

    if not project.is_dir():
        print("render: not a directory: %s" % project, file=sys.stderr)
        return 2
    _cleanup_leftovers(project)
    paths = AuditPaths.for_project(project)
    errors = render_all(paths)
    if errors:
        print("\n".join(errors))
        return 1
    print("Wrote %s and %s" % (paths.audit / "AUDIT_REPORT.md", paths.audit / "REMEDIATION_PLAN.md"))
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "readiness":
        return cmd_readiness(args)
    if args.command == "discover":
        return cmd_discover(args.project)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "test":
        return cmd_test(args)
    if args.command == "validate":
        return cmd_validate(args.project)
    return cmd_render(args.project)


if __name__ == "__main__":
    sys.exit(main())
