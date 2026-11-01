"""Parsers for test-result and coverage files produced by the test run.

Inputs come from the audited project's own test run, so they are untrusted: sizes are capped and
XML with entity declarations is rejected.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

MAX_BYTES = 50_000_000


def _read(path) -> bytes:
    p = Path(path)
    if p.stat().st_size > MAX_BYTES:
        raise ValueError("%s is larger than %d bytes" % (p.name, MAX_BYTES))
    return p.read_bytes()


def _json(path) -> dict:
    data = json.loads(_read(path).decode("utf-8", errors="replace"))
    if not isinstance(data, dict):
        raise ValueError("%s: expected a JSON object" % Path(path).name)
    return data


def parse_junit(path) -> dict:
    raw = _read(path)
    if b"<!ENTITY" in raw or b"<!DOCTYPE" in raw:
        raise ValueError("%s: DTD/entity declarations are not accepted" % Path(path).name)
    root = ET.fromstring(raw)
    counts = {"passed": 0, "failed": 0, "skipped": 0, "errors": 0}
    for case in root.iter("testcase"):
        tags = {child.tag for child in case}
        if "error" in tags:
            counts["errors"] += 1
        elif "failure" in tags:
            counts["failed"] += 1
        elif "skipped" in tags:
            counts["skipped"] += 1
        else:
            counts["passed"] += 1
    return counts


def parse_jest_json(path) -> dict:
    data = _json(path)
    suite_errors = sum(1 for s in data.get("testResults", [])
                       if s.get("status") == "failed" and not s.get("assertionResults"))
    return {"passed": int(data.get("numPassedTests", 0)),
            "failed": int(data.get("numFailedTests", 0)),
            "skipped": int(data.get("numPendingTests", 0)) + int(data.get("numTodoTests", 0)),
            "errors": suite_errors}


def _pct(covered, total) -> float:
    return round(covered / total * 100.0, 2) if total else 0.0


def parse_coveragepy(path) -> dict:
    data = _json(path)
    totals = data["totals"]
    branches = totals.get("num_branches") or 0
    return {"line_pct": _pct(totals["covered_lines"], totals["num_statements"]),
            "branch_pct": _pct(totals.get("covered_branches", 0), branches) if branches else None,
            "files": len(data.get("files", {}))}


def _istanbul_pct(entry) -> float:
    pct = entry.get("pct")
    if isinstance(pct, bool) or not isinstance(pct, (int, float)):
        raise ValueError("coverage percentage is not numeric: %r" % (pct,))
    return float(pct)


def parse_istanbul_summary(path) -> dict:
    data = _json(path)
    total = data["total"]
    branches = total.get("branches", {})
    return {"line_pct": _istanbul_pct(total["lines"]),
            "branch_pct": _istanbul_pct(branches) if branches.get("total") else None,
            "files": len(data) - 1}
