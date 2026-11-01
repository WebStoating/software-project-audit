"""One parser per scanner: raw tool output -> normalized Leads. A lead is not a finding.

Parsers never copy source text or secret values into a Lead, make paths project-relative
(the scanner container mounts the project at /src) and raise ValueError on malformed output.
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path

from .models import Lead

LIZARD_CCN_MAX = 15
LIZARD_NLOC_MAX = 100

_CWE_RE = re.compile(r"CWE-(\d+)", re.I)
_OWASP_RE = re.compile(r"^A(\d{2}):(\d{4})")
_SEMGREP_SEVERITY = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}
_BANDIT_SEVERITY = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
_HADOLINT_SEVERITY = {"error": "High", "warning": "Medium", "info": "Low", "style": "Info"}
_ZIZMOR_SEVERITY = {"High": "High", "Medium": "Medium", "Low": "Low", "Informational": "Info"}
# Trivy uses the same five levels for vulnerabilities, misconfigurations and license categories
# (forbidden=CRITICAL, restricted=HIGH, reciprocal=MEDIUM, notice=LOW); UNKNOWN maps to no hint.
_TRIVY_SEVERITY = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}


def _load(path: Path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("invalid JSON in %s: %s" % (Path(path).name, exc)) from exc


def _rel(path):
    """Project-relative path: strip the container's /src/ mount prefix."""
    if not path:
        return None
    p = str(path).replace("\\", "/")
    if p.startswith("/src/"):
        return p[len("/src/"):]
    if p == "/src":
        return "."
    return p


def _cwes(values) -> list:
    out = []
    for v in values or []:
        m = _CWE_RE.search(str(v))
        if m:
            tag = "CWE-%d" % int(m.group(1))
            if tag not in out:
                out.append(tag)
    return out


def _owasp(values):
    """(OWASP 2025 tags, OWASP 2021 tags). Other editions are dropped."""
    y2025, y2021 = [], []
    for v in values or []:
        m = _OWASP_RE.match(str(v).strip())
        if not m:
            continue
        tag = "A%s:%s" % (m.group(1), m.group(2))
        if m.group(2) == "2025" and tag not in y2025:
            y2025.append(tag)
        elif m.group(2) == "2021" and tag not in y2021:
            y2021.append(tag)
    return y2025, y2021


def _cvss_band(score) -> "str | None":
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9.0:
        return "Critical"
    if s >= 7.0:
        return "High"
    if s >= 4.0:
        return "Medium"
    return "Low" if s > 0 else None


def parse_semgrep(path: Path) -> list:
    leads = []
    for r in _load(path).get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        owasp, owasp_2021 = _owasp(meta.get("owasp"))
        lead_extra = {}
        if owasp_2021:
            lead_extra["owasp_2021"] = owasp_2021
        if meta.get("confidence"):
            lead_extra["confidence"] = meta["confidence"]
        leads.append(Lead(
            tool="semgrep", rule_id=r.get("check_id", ""), message=extra.get("message", ""),
            path=_rel(r.get("path")), start_line=r.get("start", {}).get("line"),
            end_line=r.get("end", {}).get("line"),
            severity_hint=_SEMGREP_SEVERITY.get(extra.get("severity")),
            cwe=_cwes(meta.get("cwe")), owasp=owasp, extra=lead_extra))
    return leads


def parse_bandit(path: Path) -> list:
    leads = []
    for r in _load(path).get("results", []):
        cwe = r.get("issue_cwe") or {}
        lines = r.get("line_range") or []
        leads.append(Lead(
            tool="bandit", rule_id=r.get("test_id", ""), message=r.get("issue_text", ""),
            path=_rel(r.get("filename")), start_line=r.get("line_number"),
            end_line=max(lines) if lines else r.get("line_number"),
            severity_hint=_BANDIT_SEVERITY.get(r.get("issue_severity")),
            cwe=_cwes(["CWE-%s" % cwe["id"]] if cwe.get("id") else []),
            extra={"test_name": r.get("test_name"), "confidence": r.get("issue_confidence")}))
    return leads


def parse_osv(path: Path) -> list:
    leads = []
    for res in _load(path).get("results", []):
        source = _rel((res.get("source") or {}).get("path"))
        for pkg in res.get("packages", []):
            info = pkg.get("package", {})
            vulns = {v.get("id"): v for v in pkg.get("vulnerabilities", [])}
            groups = pkg.get("groups") or [{"ids": [i]} for i in vulns]
            for g in groups:
                members = [vulns[i] for i in g.get("ids", []) if i in vulns]
                if not members:
                    continue
                first = members[0]
                cwes = []
                fixed = set()
                for v in members:
                    cwes += (v.get("database_specific") or {}).get("cwe_ids", [])
                    for a in v.get("affected", []):
                        for rng in a.get("ranges", []):
                            fixed.update(e["fixed"] for e in rng.get("events", []) if "fixed" in e)
                leads.append(Lead(
                    tool="osv-scanner", rule_id=g["ids"][0],
                    message="%s %s: %s" % (info.get("name"), info.get("version"),
                                           first.get("summary") or first.get("id")),
                    path=source, severity_hint=_cvss_band(g.get("max_severity")), cwe=_cwes(cwes),
                    extra={"package": info.get("name"), "version": info.get("version"),
                           "ecosystem": info.get("ecosystem"), "ids": g.get("ids", []),
                           "aliases": g.get("aliases", []), "fixed_versions": sorted(fixed)}))
    return leads


def parse_gitleaks(path: Path) -> list:
    """Secret and Match are never read: only where a secret is, never what it is."""
    leads = []
    for f in _load(path) or []:
        extra = {"entropy": f.get("Entropy")}
        if f.get("Commit"):
            extra["commit"] = f["Commit"][:12]
        leads.append(Lead(
            tool="gitleaks", rule_id=f.get("RuleID", ""), message=f.get("Description", ""),
            path=_rel(f.get("File")), start_line=f.get("StartLine"), end_line=f.get("EndLine"),
            severity_hint="High", extra=extra))
    return leads


def parse_checkov(path: Path) -> list:
    doc = _load(path)
    reports = doc if isinstance(doc, list) else [doc]
    leads = []
    for rep in reports:
        for c in (rep.get("results") or {}).get("failed_checks", []):
            rng = c.get("file_line_range") or [None, None]
            start, end = (rng + [None, None])[:2]
            leads.append(Lead(
                tool="checkov", rule_id=c.get("check_id", ""), message=c.get("check_name", ""),
                path=_rel(c.get("file_abs_path")) or (c.get("file_path") or "").lstrip("/") or None,
                start_line=start or None, end_line=end or None,
                extra={"framework": rep.get("check_type"), "resource": c.get("resource"),
                       "guideline": c.get("guideline")}))
    return leads


def parse_hadolint(path: Path) -> list:
    return [Lead(
        tool="hadolint", rule_id=f.get("code", ""), message=f.get("message", ""),
        path=_rel(f.get("file")), start_line=f.get("line"), end_line=f.get("line"),
        severity_hint=_HADOLINT_SEVERITY.get(f.get("level"))) for f in _load(path) or []]


def parse_zizmor(path: Path) -> list:
    leads = []
    for f in _load(path) or []:
        if f.get("ignored"):
            continue
        locs = f.get("locations") or []
        loc = next((x for x in locs if x.get("symbolic", {}).get("kind") == "Primary"),
                   locs[0] if locs else {})
        sym = loc.get("symbolic", {})
        key = sym.get("key", {})
        fpath = (key.get("Local") or {}).get("verbatim_path") or (key.get("Local") or {}).get("given_path")
        pts = loc.get("concrete", {}).get("location", {})
        start = (pts.get("start_point") or {}).get("row")
        end = (pts.get("end_point") or {}).get("row")
        det = f.get("determinations", {})
        leads.append(Lead(
            tool="zizmor", rule_id=f.get("ident", ""), message=f.get("desc", ""),
            path=_rel(fpath), start_line=start + 1 if start is not None else None,
            end_line=end + 1 if end is not None else None,
            severity_hint=_ZIZMOR_SEVERITY.get(det.get("severity")),
            extra={"url": f.get("url"), "confidence": det.get("confidence"),
                   "persona": det.get("persona"), "annotation": sym.get("annotation")}))
    return leads


def parse_actionlint(path: Path) -> list:
    return [Lead(
        tool="actionlint", rule_id=f.get("kind", "") or "syntax", message=f.get("message", ""),
        path=_rel(f.get("filepath")), start_line=f.get("line"), end_line=f.get("line"),
        extra={"column": f.get("column")}) for f in _load(path) or []]


def parse_lizard(path: Path) -> list:
    """Lizard lists every function; only complexity or size outliers become leads."""
    leads = []
    with Path(path).open(encoding="utf-8", newline="") as fh:
        for row in csv.reader(fh):
            if len(row) < 11:
                continue
            nloc, ccn = int(row[0]), int(row[1])
            if ccn <= LIZARD_CCN_MAX and nloc <= LIZARD_NLOC_MAX:
                continue
            rule = "lizard.ccn" if ccn > LIZARD_CCN_MAX else "lizard.nloc"
            leads.append(Lead(
                tool="lizard", rule_id=rule,
                message="%s: cyclomatic complexity %d, %d lines of code" % (row[7], ccn, nloc),
                path=_rel(row[6]), start_line=int(row[9]), end_line=int(row[10]),
                extra={"function": row[7], "ccn": ccn, "nloc": nloc, "params": int(row[3])}))
    return leads


def parse_jscpd(path: Path) -> list:
    leads = []
    for d in _load(path).get("duplicates", []):
        a, b = d.get("firstFile", {}), d.get("secondFile", {})
        leads.append(Lead(
            tool="jscpd", rule_id="duplication",
            message="%d duplicated lines (%d tokens) also at %s:%s-%s" % (
                d.get("lines", 0), d.get("tokens", 0), b.get("name"), b.get("start"), b.get("end")),
            path=_rel(a.get("name")), start_line=a.get("start"), end_line=a.get("end"),
            extra={"other_path": _rel(b.get("name")), "other_start_line": b.get("start"),
                   "other_end_line": b.get("end"), "lines": d.get("lines"), "tokens": d.get("tokens"),
                   "format": d.get("format")}))
    return leads


def parse_ruff(path: Path) -> list:
    leads = []
    for f in _load(path) or []:
        loc, end = f.get("location") or {}, f.get("end_location") or {}
        leads.append(Lead(
            tool="ruff", rule_id=f.get("code") or "", message=f.get("message", ""),
            path=_rel(f.get("filename")), start_line=loc.get("row"), end_line=end.get("row"),
            extra={"name": f.get("name"), "url": f.get("url")}))
    return leads


def parse_trivy(path: Path) -> list:
    """`trivy fs` JSON: vulnerabilities, failed misconfiguration checks and package licenses.

    Secret scanning is off (Gitleaks is the single secrets source) and misconfiguration code lines
    are scrubbed from the stored report, so no source text is read here.
    """
    leads = []
    for res in _load(path).get("Results") or []:
        target = _rel(res.get("Target"))
        for v in res.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID", "")
            leads.append(Lead(
                tool="trivy", rule_id=vid,
                message="%s %s: %s" % (v.get("PkgName"), v.get("InstalledVersion"), v.get("Title") or vid),
                path=target, severity_hint=_TRIVY_SEVERITY.get(v.get("Severity")),
                cwe=_cwes(v.get("CweIDs")),
                extra={"package": v.get("PkgName"), "installed_version": v.get("InstalledVersion"),
                       "fixed_version": v.get("FixedVersion"), "vuln_id": vid,
                       "aliases": list(v.get("VendorIDs") or []), "url": v.get("PrimaryURL")}))
        for m in res.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            cause = m.get("CauseMetadata") or {}
            extra = {"type": m.get("Type"), "url": m.get("PrimaryURL"), "resolution": m.get("Resolution")}
            if m.get("AVDID"):
                extra["avd_id"] = m["AVDID"]
            leads.append(Lead(
                tool="trivy", rule_id=m.get("ID") or m.get("AVDID") or "",
                message="%s: %s" % (m.get("Title", ""), m.get("Message", "")),
                path=target, start_line=cause.get("StartLine") or None, end_line=cause.get("EndLine") or None,
                severity_hint=_TRIVY_SEVERITY.get(m.get("Severity")), extra=extra))
        for lic in res.get("Licenses") or []:
            leads.append(Lead(
                tool="trivy", rule_id="license:%s" % lic.get("Name", ""),
                message="%s license (%s) for %s" % (lic.get("Name"), lic.get("Category"),
                                                    lic.get("PkgName") or lic.get("FilePath")),
                path=_rel(lic.get("FilePath")) or target,
                severity_hint=_TRIVY_SEVERITY.get(lic.get("Severity")),
                extra={"package": lic.get("PkgName") or None, "category": lic.get("Category"),
                       "license": lic.get("Name")}))
    return leads
