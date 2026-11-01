import json
import re

import pytest

from auditlib.jsonschema_lite import validate


@pytest.fixture
def findings_schema(skill_root):
    return json.loads((skill_root / "assets" / "findings.schema.json").read_text(encoding="utf-8"))


@pytest.fixture
def finding(skill_root):
    text = (skill_root / "references" / "methodology.md").read_text(encoding="utf-8")
    sec = text.split("### 7.6 Finding JSON contract", 1)[1]
    block = re.search(r"```json\n(.*?)\n```", sec, re.S).group(1)
    return json.loads(block)


def test_methodology_example_validates(finding, findings_schema):
    assert validate(finding, findings_schema) == []


def test_missing_evidence(finding, findings_schema):
    del finding[0]["evidence"]
    assert any("evidence" in e for e in validate(finding, findings_schema))


def test_bad_severity(finding, findings_schema):
    finding[0]["severity"] = "Severe"
    errs = validate(finding, findings_schema)
    assert any("severity" in e and "enum" in e for e in errs)


def test_unknown_domain_name_rejected(finding, findings_schema):
    finding[0]["domain"] = "Testing"
    assert any("domain" in e for e in validate(finding, findings_schema))


def test_coverage_minimal(skill_root):
    s = json.loads((skill_root / "assets" / "coverage.schema.json").read_text(encoding="utf-8"))
    doc = {
        "scope": "repo only",
        "domains": [
            {"id": "D01", "applicable": True, "maturity": 3, "checks": [{"id": "ARC-01", "outcome": "verified_pass", "evidence": [], "note": ""}]},
            {"id": "D02", "applicable": True, "maturity": "Not verified"},
        ],
        "readiness": {"decision": "Ready with conditions", "goal": "MVP", "conditions": [], "blockers": []},
        "subagents": {"used": False, "briefs": []},
    }
    assert validate(doc, s) == []
    doc["domains"][0]["maturity"] = 7
    assert validate(doc, s)
    doc["domains"][0]["maturity"] = 3
    doc["domains"][0]["id"] = "D12"
    assert validate(doc, s)
