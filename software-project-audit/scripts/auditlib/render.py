"""Render AUDIT_REPORT.md and REMEDIATION_PLAN.md from validated JSON plus agent-written narrative."""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import SKILL_ROOT, SKILL_VERSION, dockerutil
from .discover import EXCLUDED_DIRS
from .ledger import load_runs
from .models import DOMAINS, PRIORITIES, SEVERITIES
from .paths import AuditPaths
from .standards import load_standards
from .validate import validate_audit

NARRATIVES = ("executive_summary", "architecture", "domain_assessments", "testing_confidence",
              "conclusions", "remediation_notes", "open_questions")
NA = "not available"
NETWORK_NOTE = ("Scanners and the test run had network access. Dependency vulnerability lookups sent "
                "package names and versions (no source code) to public advisory databases; no tool uploaded "
                "source code. The code was read and processed by %s using %s.")
_PLACEHOLDER = re.compile(r"\{\{([a-z_0-9]+(?::[a-z_]+)?)\}\}")
_AUD = re.compile(r"AUD-\d{3}")


def _cell(value) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\r\n", "<br>").replace("\r", "<br>").replace("\n", "<br>")


def md_table(headers, rows) -> str:
    lines = ["| " + " | ".join(_cell(h) for h in headers) + " |",
             "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(_cell(c) for c in row) + " |")
    return "\n".join(lines)


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _prio_key(f) -> int:
    p = f.get("priority")
    return PRIORITIES.index(p) if p in PRIORITIES else len(PRIORITIES)


def _sev_key(f) -> int:
    return SEVERITIES.index(f["severity"])


def _ids(values) -> str:
    return ", ".join(values) if values else "—"


def _evidence(f) -> str:
    return "<br>".join("%s:%s" % (e["path"], e["line"]) if e.get("line") else e["path"] for e in f["evidence"])


# ---- deterministic blocks -------------------------------------------------------------------------

def _scanner_digest(paths: AuditPaths) -> str:
    # The scan step records no image digest in the ledger, so ask Docker (None when absent).
    return dockerutil.image_digest(dockerutil.SCANNER_IMAGE) or NA


def _audit_date(paths: AuditPaths, ctx: dict, runs) -> str:
    stamps = sorted(r.started_at for r in runs if r.started_at)
    if stamps:
        return stamps[0][:10]
    return str(ctx.get("date") or NA)


def scope_table(paths, ctx, inventory, runs, test_results) -> str:
    git = inventory.get("git") or {}
    if git.get("is_repo"):
        revision = "%s on %s%s" % (git.get("commit") or NA, git.get("branch") or "detached HEAD",
                                   ", uncommitted changes present" if git.get("dirty") else ", clean")
    elif inventory:
        revision = "not a git repository"
    else:
        revision = NA
    runtimes = sorted({r["runtime_version"] for r in test_results.get("results", []) if r.get("runtime_version")})
    ran = bool(test_results.get("results"))
    unsupported = inventory.get("unsupported_stacks") or []
    unsupported = [u if isinstance(u, str) else json.dumps(u, sort_keys=True) for u in unsupported]
    assumptions = ctx.get("assumptions") or []
    rows = [
        ("Target path", str(paths.project.resolve())),
        ("Revision", revision),
        ("Audit date", _audit_date(paths, ctx, runs)),
        ("Skill version", SKILL_VERSION),
        ("Audit goal", ctx.get("goal") or NA),
        ("Stage", ctx.get("stage") or NA),
        ("Assumptions", "<br>".join(assumptions) if assumptions else "none recorded"),
        ("Scanner image", "%s (%s)" % (dockerutil.SCANNER_IMAGE, _scanner_digest(paths))),
        ("Test environment", "developer's machine (local environment); runtimes: %s"
         % (", ".join(runtimes) or "not recorded") if ran
         else "none (the developer declined the test run; no project code was executed)"
         if ctx.get("test_run_consent") is False else "none (no tests were run)"),
        ("Network and LLM processing", NETWORK_NOTE % (ctx.get("agent"), ctx.get("model_provider"))),
        ("Unsupported stacks", ", ".join(sorted(unsupported)) if unsupported else "none detected"),
        ("Excluded paths", ", ".join(sorted(EXCLUDED_DIRS) + ["audit"])),
    ]
    return md_table(["Item", "Value"], rows)


def scorecard(cov) -> str:
    rows = []
    for d in sorted(cov["domains"], key=lambda d: d["id"]):
        if d["applicable"]:
            rows.append((d["id"], DOMAINS.get(d["id"], ""), d.get("maturity", "Not verified"),
                         d.get("confidence", "—"), d.get("rationale", "")))
        else:
            rows.append((d["id"], DOMAINS.get(d["id"], ""), "Not applicable", "—", d.get("reason", "")))
    out = md_table(["Domain", "Name", "Maturity (0-4)", "Confidence", "Rationale"], rows)
    ready = cov.get("readiness")
    if ready:
        out = "**Readiness for the stated goal (%s):** %s\n\n%s" % (ready.get("goal", NA), ready["decision"], out)
    return out


def key_findings(findings) -> str:
    key = sorted((f for f in findings if f["severity"] in ("Critical", "High")),
                 key=lambda f: (_prio_key(f), _sev_key(f), f["id"]))
    if not key:
        return "No Critical or High findings were recorded."
    return md_table(["ID", "Title", "Severity", "Priority", "Confidence", "Impact", "Recommendation"],
                    [(f["id"], f["title"], f["severity"], f.get("priority", "—"), f["confidence"],
                      f["impact"], f["recommendation"]) for f in key])


def test_results_block(test_results, declined: bool = False) -> str:
    if declined:
        return "The developer declined the unit-test run, so no project code was executed and no coverage was measured."
    if not test_results:
        return "No test results were recorded (`raw/test-results.json` is absent)."
    results = sorted(test_results.get("results", []), key=lambda r: r["package_path"])
    rows = []
    for r in results:
        c = r.get("counts")
        cov = r.get("coverage")
        rows.append((r["package_path"], r.get("runtime_version") or "—", r["status"],
                     "—" if not c else "%d / %d / %d / %d" % (c["passed"], c["failed"], c["errors"], c["skipped"]),
                     "—" if not cov else "%.1f%%" % cov["line_pct"]))
    out = md_table(["Package", "Runtime", "Status", "Passed / failed / errors / skipped", "Line coverage"], rows) \
        if rows else "No test runs were executed."
    notes = ["- `%s`: %s" % (r["package_path"], n) for r in results for n in r.get("notes") or []
             if n.startswith(("tests modified the working tree", "WARNING"))]
    if notes:
        out += "\n\nObserved during the test run:\n\n" + "\n".join(notes)
    suggestions = coverage_tool_suggestions(test_results, empty="")
    if suggestions:
        out += "\n\nSuggested to the developer:\n\n" + suggestions
    skipped = test_results.get("skipped") or []
    if skipped:
        out += "\n\nSkipped packages:\n\n" + md_table(
            ["Package", "Reason"], [(s["package_path"], s["reason"]) for s in sorted(skipped, key=lambda s: s["package_path"])])
    return out


def coverage_tool_suggestions(test_results, empty: str = "No developer actions were recorded.") -> str:
    lines = ["- `%s`: %s" % (r["package_path"], r["coverage_tool_suggestion"])
             for r in sorted(test_results.get("results", []), key=lambda r: r["package_path"])
             if r.get("coverage_tool_suggestion")]
    return "\n".join(lines) if lines else empty


def standards_matrix(cov) -> str:
    std = load_standards()
    entries = cov.get("standards") or {}
    parts = []
    for title, std_key, cov_key in (("OWASP Top 10:2025", "owasp_top10_2025", "owasp"),
                                    ("CWE Top 25", "cwe_top25", "cwe")):
        by_id = {e["id"]: e for e in entries.get(cov_key, [])}
        rows = []
        for item in std[std_key]["items"]:
            e = by_id.get(item["id"], {})
            rows.append((item["id"], item["name"], e.get("outcome", "not recorded"), e.get("method", "—"),
                         _ids(e.get("findings"))))
        parts.append("#### %s\n\n%s" % (title, md_table(["ID", "Name", "Outcome", "Method", "Findings"], rows)))
    return "\n\n".join(parts)


def findings_register(findings) -> str:
    return md_table(
        ["ID", "Title", "Domain", "Severity", "Confidence", "Status", "Classification", "Priority", "Effort",
         "Evidence", "Recommendation"],
        [(f["id"], f["title"], f["domain"], f["severity"], f["confidence"], f["status"],
          f.get("classification", "—"), f.get("priority", "—"), f.get("effort", "Unknown"), _evidence(f),
          f["recommendation"]) for f in sorted(findings, key=lambda f: f["id"])])


def tool_ledger(runs) -> str:
    if not runs:
        return "No tool runs were recorded."
    return md_table(["Tool", "Version", "Status", "Exit code", "Duration (s)", "Counts", "Note"],
                    [(r.tool, r.version or "—", r.status, "—" if r.exit_code is None else r.exit_code,
                      r.duration_s, ", ".join("%s=%s" % kv for kv in sorted(r.counts.items())) or "—",
                      r.reason or "") for r in runs])


def coverage_appendix(cov) -> str:
    outcomes = ("verified_pass", "verified_fail", "reviewed_no_issue", "needs_verification", "not_reviewed",
                "not_applicable")
    rows, open_checks, blind = [], [], []
    for d in sorted(cov["domains"], key=lambda d: d["id"]):
        counts = {o: 0 for o in outcomes}
        for c in d.get("checks", []):
            counts[c["outcome"]] += 1
            if c["outcome"] in ("needs_verification", "not_reviewed"):
                open_checks.append((c["id"], c["outcome"], c.get("note", "")))
        rows.append([d["id"], DOMAINS.get(d["id"], "")] + [counts[o] for o in outcomes])
        blind += [(d["id"], b) for b in d.get("blind_spots", [])]
    scope = cov["scope"]
    parts = ["**Scope:** %s" % (scope if isinstance(scope, str) else json.dumps(scope, sort_keys=True)),
             "**Checks per domain by outcome**\n\n" + md_table(["Domain", "Name"] + list(outcomes), rows)]
    wf = cov.get("workflows") or []
    if wf:
        parts.append("**Critical workflows**\n\n" + md_table(
            ["Workflow", "Entry point", "Traced", "Findings", "Note"],
            [(w["name"], w.get("entry_point", "—"), "yes" if w.get("traced") else "no", _ids(w.get("findings")),
              w.get("note", "")) for w in sorted(wf, key=lambda w: w["name"])]))
    if open_checks:
        parts.append("**Checks not yet verified**\n\n" + md_table(["Check", "Outcome", "Note"], sorted(open_checks)))
    if blind:
        parts.append("**Blind spots**\n\n" + md_table(["Domain", "Blind spot"], blind))
    ready = cov.get("readiness") or {}
    items = [("Condition", c) for c in ready.get("conditions", [])] + [("Blocker", b) for b in ready.get("blockers", [])]
    if items:
        parts.append("**Readiness: %s**\n\n" % ready["decision"] + md_table(["Kind", "Text"], items))
    return "\n\n".join(parts)


GROUPS = (("p0", ("P0",)), ("p1", ("P1",)), ("p2_p3", ("P2", "P3", None)))


def _group(findings, prios):
    sel = [f for f in findings if (f.get("priority") if f.get("priority") in PRIORITIES else None) in prios]
    return sorted(sel, key=lambda f: (_prio_key(f), _sev_key(f), f["id"]))


def _plan_table(group) -> str:
    if not group:
        return "None."
    return md_table(
        ["Finding", "Desired outcome", "Verification steps", "Dependencies", "Effort", "Priority"],
        [(f["id"] + ": " + f["title"], f["recommendation"],
          "<br>".join(f.get("verification_steps") or []) or "—", _ids(f.get("related_findings")),
          f.get("effort", "Unknown"), f.get("priority", "unassigned")) for f in group])


def roadmap_summary(findings) -> str:
    rows = []
    for label, (key, prios) in zip(("Immediate / blocking", "Near-term stabilization", "Strategic evolution"), GROUPS):
        g = _group(findings, prios)
        rows.append((label, "/".join(p for p in prios if p), len(g), _ids([f["id"] for f in g])))
    return md_table(["Horizon", "Priority", "Findings", "IDs"], rows)


# ---- assembly ---------------------------------------------------------------------------------------

def _fill(template: str, blocks: dict, narratives: dict, missing: list) -> str:
    def sub(m):
        key = m.group(1)
        if key.startswith("narrative:"):
            name = key.split(":", 1)[1]
            text = narratives.get(name)
            if text is None:
                if name not in missing:
                    missing.append(name)
                return "> ⚠ MISSING NARRATIVE: %s" % name
            return text
        return blocks[key]
    return _PLACEHOLDER.sub(sub, template)


def _load_narratives(paths: AuditPaths) -> dict:
    out = {}
    for name in NARRATIVES:
        p = paths.raw / "narrative" / (name + ".md")
        try:
            text = p.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if text:
            out[name] = text
    return out


def render_all(paths: AuditPaths) -> list[str]:
    errors = validate_audit(paths)
    if errors:
        return errors
    findings = json.loads((paths.audit / "FINDINGS.json").read_text(encoding="utf-8"))
    cov = json.loads((paths.audit / "AUDIT_COVERAGE.json").read_text(encoding="utf-8"))
    ctx = json.loads((paths.raw / "context.json").read_text(encoding="utf-8"))
    inventory = _read_json(paths.raw / "inventory.json", {})
    test_results = _read_json(paths.raw / "test-results.json", {})
    runs = load_runs(paths.raw)
    narratives = _load_narratives(paths)

    blocks = {
        "scope_table": scope_table(paths, ctx, inventory, runs, test_results),
        "scorecard": scorecard(cov),
        "key_findings": key_findings(findings),
        "test_results": test_results_block(test_results, declined=ctx.get("test_run_consent") is False),
        "standards_matrix": standards_matrix(cov),
        "findings_register": findings_register(findings),
        "tool_ledger": tool_ledger(runs),
        "coverage_appendix": coverage_appendix(cov),
        "roadmap_summary": roadmap_summary(findings),
        "coverage_tool_suggestions": coverage_tool_suggestions(test_results),
    }
    for key, prios in GROUPS:
        blocks["plan_" + key] = _plan_table(_group(findings, prios))

    missing: list[str] = []
    assets = SKILL_ROOT / "assets"
    for template, target in (("AUDIT_REPORT.template.md", "AUDIT_REPORT.md"),
                             ("REMEDIATION_PLAN.template.md", "REMEDIATION_PLAN.md")):
        text = (assets / template).read_text(encoding="utf-8")
        (paths.audit / target).write_text(_fill(text, blocks, narratives, missing).rstrip("\n") + "\n",
                                          encoding="utf-8")

    problems = ["missing or empty narrative fragment: raw/narrative/%s.md" % n for n in missing]
    known = {f["id"] for f in findings}
    for name in sorted(narratives):
        for fid in sorted(set(_AUD.findall(narratives[name])) - known):
            problems.append("narrative %s cites %s, which is not in FINDINGS.json" % (name, fid))
    summary = narratives.get("executive_summary")
    if summary is not None:
        cited = set(_AUD.findall(summary))
        for f in sorted(findings, key=lambda f: f["id"]):
            if f.get("priority") == "P0" and f["id"] not in cited:
                problems.append("narrative executive_summary must cite P0 finding %s" % f["id"])
    return problems
