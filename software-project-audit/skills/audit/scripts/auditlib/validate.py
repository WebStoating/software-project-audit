"""Mechanical enforcement of the methodology's evidence and coverage rules on a draft audit."""
from __future__ import annotations

import json
import math
import re
from pathlib import Path

from . import SKILL_ROOT
from .jsonschema_lite import validate as schema_errors
from .ledger import load_runs
from .methodology import load_check_ids
from .models import DOMAINS
from .paths import AuditPaths
from .standards import cwe_ids, owasp_ids

# Secret hygiene (rule 14). Regex and entropy threshold copied from the gitleaks "generic-api-key" rule
# of the version pinned in assets/tool-versions.json (v8.30.1):
# https://github.com/gitleaks/gitleaks/blob/v8.30.1/config/gitleaks.toml  ([[rules]] id = "generic-api-key")
# The rule's `^[a-zA-Z_.-]+$` allowlist (letters only secrets) is applied too. The rule's other
# allowlists and stopwords are not copied, so this errs on the side of reporting.
GENERIC_API_KEY = re.compile(
    r"""(?i)[\w.-]{0,50}?(?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)"""
    r"""(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}"""
    r"""([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:[\x60'"\s;]|\\[nr]|$)"""
)
_LETTERS_ONLY = re.compile(r"^[a-zA-Z_.-]+$")
ENTROPY_THRESHOLD = 3.5  # Shannon, bits per character; gitleaks skips secrets at or below it

_VERIFIED = ("verified_pass", "verified_fail")


def _entropy(s: str) -> float:
    n = len(s)
    return -sum(s.count(c) / n * math.log2(s.count(c) / n) for c in set(s))


def _load(path: Path, label: str, errors: list):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        errors.append("%s: file not found (%s)" % (label, path))
    except (OSError, ValueError) as e:
        errors.append("%s: cannot read: %s" % (label, e))
    return None


def _schema(name: str) -> dict:
    return json.loads((SKILL_ROOT / "assets" / name).read_text(encoding="utf-8"))


def _line_count(p: Path) -> int:
    data = p.read_bytes()
    return data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)


def _check_evidence_path(project: Path, ev: dict, fid: str, errors: list) -> None:
    raw = ev["path"]
    if Path(raw).is_absolute() or re.match(r"^[A-Za-z]:[\\/]", raw):
        errors.append("%s: evidence path %s is absolute; use a path relative to the project" % (fid, raw))
        return
    try:
        root = project.resolve()
        target = (root / raw).resolve()
        target.relative_to(root)
    except ValueError:
        errors.append("%s: evidence path %s resolves outside the project" % (fid, raw))
        return
    except OSError as e:
        errors.append("%s: evidence path %s cannot be resolved: %s" % (fid, raw, e))
        return
    if not target.exists():
        errors.append("%s: evidence path %s does not exist in the project" % (fid, raw))
        return
    if not target.is_file():
        return
    try:
        lines = _line_count(target)
    except OSError as e:
        errors.append("%s: evidence path %s cannot be read: %s" % (fid, raw, e))
        return
    for key in ("line", "end_line"):
        if key in ev and ev[key] > lines:
            errors.append("%s: evidence %s %d is beyond the end of %s (%d lines)" % (fid, key, ev[key], raw, lines))


def _check_findings(findings: list, paths: AuditPaths, errors: list) -> None:
    seen = set()
    for f in findings:
        if f["id"] in seen:
            errors.append("duplicate finding id %s" % f["id"])
        seen.add(f["id"])
    leads = _load_optional(paths.raw / "leads.json")
    lead_ids = {l.get("id") for l in leads if isinstance(l, dict)} if isinstance(leads, list) else set()
    try:
        tools = {r.tool for r in load_runs(paths.raw)}
    except (OSError, ValueError, TypeError) as e:
        errors.append("run-ledger.json: cannot read: %s" % e)
        tools = set()
    for f in findings:
        for ref in f.get("tool_refs", []):
            if ref not in lead_ids and ref not in tools:
                errors.append("%s: tool_refs entry %s is neither a lead id in leads.json nor a tool in "
                              "run-ledger.json" % (f["id"], ref))
        for ev in f["evidence"]:
            _check_evidence_path(paths.project, ev, f["id"], errors)
            ref = ev.get("tool_ref")
            if ref is not None and ref not in lead_ids and ref not in tools:
                errors.append("%s: evidence tool_ref %s is neither a lead id in leads.json nor a tool in "
                              "run-ledger.json" % (f["id"], ref))
        if f.get("priority") == "P0" and f["severity"] not in ("Critical", "High") and not f.get("root_cause", "").strip():
            errors.append("%s: P0 finding with severity %s needs a root_cause stating why it blocks"
                          % (f["id"], f["severity"]))


def _load_optional(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _check_coverage(cov: dict, findings: list, paths: AuditPaths, errors: list) -> None:
    expected = load_check_ids()
    domains = {d["id"]: d for d in cov["domains"]}
    for did in DOMAINS:
        if did not in domains:
            errors.append("coverage: domain %s (%s) is missing" % (did, DOMAINS[did]))
    outcomes = {}
    for did, d in domains.items():
        checks = d.get("checks", [])
        listed = [c["id"] for c in checks]
        for c in checks:
            if c["id"] not in expected.get(did, []):
                errors.append("coverage: unknown check ID %s in %s" % (c["id"], did))
            if c["outcome"] in _VERIFIED and not c.get("evidence"):
                errors.append("coverage: %s is %s in %s but lists no evidence" % (c["id"], c["outcome"], did))
            outcomes[c["id"]] = c["outcome"]
        if d["applicable"]:
            for cid in expected.get(did, []):
                if cid not in listed:
                    errors.append("coverage: applicable domain %s does not list check %s" % (did, cid))
        if isinstance(d.get("maturity"), int) and not isinstance(d["maturity"], bool):
            if all(c["outcome"] == "not_reviewed" for c in checks):
                errors.append("coverage: %s has numeric maturity %d but every check is not_reviewed"
                              % (did, d["maturity"]))
    _check_test08(outcomes.get("TEST-08"), paths, errors)
    _check_declined(outcomes.get("TEST-08"), paths, errors)
    _check_standards(cov, findings, errors)
    ids = {f["id"] for f in findings}
    for w in cov.get("workflows", []):
        for fid in w.get("findings", []):
            if fid not in ids:
                errors.append("coverage: workflow '%s' references unknown finding %s" % (w["name"], fid))


def _check_test08(outcome, paths: AuditPaths, errors: list) -> None:
    if outcome not in _VERIFIED:
        return
    data = _load_optional(paths.raw / "test-results.json")
    results = data.get("results", []) if isinstance(data, dict) else []
    done = [r for r in results if isinstance(r, dict) and r.get("status") == "completed"]
    if not done:
        errors.append("coverage: TEST-08 is %s but test-results.json has no completed result" % outcome)
        return
    bad = sum((r.get("counts") or {}).get("failed", 0) + (r.get("counts") or {}).get("errors", 0) for r in done)
    if outcome == "verified_pass" and bad:
        errors.append("coverage: TEST-08 is verified_pass but test-results.json records %d failed/errored tests" % bad)
    if outcome == "verified_fail" and not bad:
        errors.append("coverage: TEST-08 is verified_fail but no completed result in test-results.json "
                      "has failures or errors")


def _check_declined(outcome, paths: AuditPaths, errors: list) -> None:
    ctx = _load_optional(paths.raw / "context.json")
    if not isinstance(ctx, dict) or ctx.get("test_run_consent") is not False:
        return
    if (paths.raw / "test-results.json").exists():
        errors.append("raw/test-results.json exists although the developer declined the test run "
                      "(context.json test_run_consent is false)")
    if outcome is not None and outcome != "not_reviewed":
        errors.append("coverage: TEST-08 is %s but the developer declined the test run; it must be not_reviewed"
                      % outcome)


def _check_standards(cov: dict, findings: list, errors: list) -> None:
    std = cov.get("standards", {})
    for key, ids in (("owasp", owasp_ids()), ("cwe", cwe_ids())):
        items = std.get(key, [])
        have = [i["id"] for i in items]
        for i in ids:
            if i not in have:
                errors.append("coverage: standards.%s is missing %s" % (key, i))
        for i in sorted(set(have) - set(ids)):
            errors.append("coverage: standards.%s lists %s, which is not in standards.json" % (key, i))
        for i in sorted({x for x in have if have.count(x) > 1}):
            errors.append("coverage: standards.%s lists %s more than once" % (key, i))
        listed = {i["id"]: set(i.get("findings", [])) for i in items}
        refs: dict = {}
        for f in findings:
            refs.setdefault(f["id"], set()).update(f.get("standards_refs", {}).get(key, []))
        for fid, rs in refs.items():
            for r in sorted(rs):
                if r in ids and fid not in listed.get(r, set()):
                    errors.append("%s: standards_refs.%s names %s but standards.%s[%s].findings does not list it"
                                  % (fid, key, r, key, r))
        for sid, fids in listed.items():
            for fid in sorted(fids):
                if fid not in refs:
                    errors.append("coverage: standards.%s[%s] lists unknown finding %s" % (key, sid, fid))
                elif sid not in refs[fid]:
                    errors.append("%s: standards.%s[%s].findings lists it but its standards_refs.%s lacks %s"
                                  % (fid, key, sid, key, sid))


def _check_context(paths: AuditPaths, errors: list) -> None:
    ctx = _load(paths.raw / "context.json", "context.json", errors)
    if ctx is None:
        return
    if not isinstance(ctx, dict):
        errors.append("context.json: must be a JSON object")
        return
    for key in ("goal", "agent", "model_provider"):
        v = ctx.get(key)
        if not isinstance(v, str) or not v.strip():
            errors.append("context.json: '%s' is missing or empty" % key)
    if not isinstance(ctx.get("test_run_consent"), bool):
        errors.append("context.json: 'test_run_consent' must be true or false (the developer's answer to running "
                      "the unit tests)")


def _string_views(node, key=None):
    """Decoded 'key: value' lines for every string in a JSON tree (raw JSON escapes quotes, hiding them)."""
    if isinstance(node, str):
        yield "%s: %s" % (key, node) if key else node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from _string_views(v, k)
    elif isinstance(node, list):
        for v in node:
            yield from _string_views(v, key)


def _secret_hits(text: str):
    for m in GENERIC_API_KEY.finditer(text):
        secret = m.group(1)
        if not _LETTERS_ONLY.match(secret) and _entropy(secret) > ENTROPY_THRESHOLD:
            yield secret, text.count("\n", 0, m.start(1)) + 1


def _check_secrets(paths: AuditPaths, errors: list) -> None:
    files = [paths.audit / "FINDINGS.json", paths.audit / "AUDIT_COVERAGE.json"]
    history = paths.audit / "history"
    for md in sorted(paths.audit.rglob("*.md")):
        if history not in md.parents:
            files.append(md)
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        found = {}
        for secret, line in _secret_hits(text):
            found.setdefault(secret, "line %d" % line)
        if f.suffix == ".json":
            try:
                views = "\n".join(_string_views(json.loads(text)))
            except ValueError:
                views = ""
            for secret, _ in _secret_hits(views):
                found.setdefault(secret, "a string value")
        for where in found.values():
            errors.append("secret hygiene: %s, %s matches the generic-api-key rule (value withheld); "
                          "remove or redact it" % (f.relative_to(paths.audit), where))


def validate_audit(paths: AuditPaths) -> list[str]:
    errors: list[str] = []
    findings = _load(paths.audit / "FINDINGS.json", "FINDINGS.json", errors)
    cov = _load(paths.audit / "AUDIT_COVERAGE.json", "AUDIT_COVERAGE.json", errors)
    _check_context(paths, errors)
    structural = False
    for data, label, schema in ((findings, "FINDINGS.json", "findings.schema.json"),
                                (cov, "AUDIT_COVERAGE.json", "coverage.schema.json")):
        if data is None:
            structural = True
            continue
        errs = schema_errors(data, _schema(schema))
        errors += ["%s: %s" % (label, e) for e in errs]
        structural = structural or bool(errs)
    if not structural:
        _check_findings(findings, paths, errors)
        _check_coverage(cov, findings, paths, errors)
    if paths.audit.is_dir():
        _check_secrets(paths, errors)
    return errors
