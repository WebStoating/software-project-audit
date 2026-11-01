import json
import sys
from pathlib import Path

from helpers import SKILL_DIR

import pytest

sys.path.insert(0, str(SKILL_DIR / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import audit  # noqa: E402
from auditlib import dockerutil  # noqa: E402
from auditlib.paths import AuditPaths  # noqa: E402
from helpers import VALID_AUDIT, build_coverage, make_fixture_repo, make_real_venv, tree_hash, write_context  # noqa: E402

pytestmark = [pytest.mark.docker, pytest.mark.hostrun]

NARRATIVES = ["executive_summary", "architecture", "domain_assessments", "testing_confidence",
              "conclusions", "remediation_notes", "open_questions"]


def _adapt_audit(paths, leads, test_results):
    """Write context, findings, coverage and narratives consistent with the real raw data of this run."""
    semgrep_leads = [lead for lead in leads
                     if lead["path"] == "app/db.py" and "semgrep" in lead["tools"] and "CWE-89" in lead["cwe"]]
    assert semgrep_leads, "no semgrep CWE-89 lead on app/db.py"
    finding = {
        "id": "AUD-001", "title": "SQL built from user input with an f-string",
        "domain": "Security and privacy", "severity": "High", "confidence": "Confirmed",
        "status": "Reviewed", "classification": "defect", "priority": "P1",
        "evidence": [{"path": "app/db.py", "line": 11,
                      "explanation": "find_user_unsafe interpolates the name into the SQL text.",
                      "tool_ref": semgrep_leads[0]["id"]}],
        "impact": "A caller-supplied name can alter the query.",
        "recommendation": "Use the parameterised query already used by find_user.",
        "standards_refs": {"owasp": ["A05:2025"], "cwe": ["CWE-89"]},
    }
    (paths.audit / "FINDINGS.json").write_text(json.dumps([finding], indent=2) + "\n", encoding="utf-8")
    (paths.raw / "context.json").write_bytes((VALID_AUDIT / "project" / "audit" / "raw" / "context.json").read_bytes())

    cov = build_coverage()
    cov["scope"] = "app/"
    cov["workflows"] = [{"name": "lookup", "entry_point": "app/db.py", "traced": True, "findings": ["AUD-001"]}]
    done = [r for r in test_results["results"] if r["status"] == "completed"]
    bad = sum(r["counts"]["failed"] + r["counts"]["errors"] for r in done)
    for d in cov["domains"]:
        for c in d["checks"]:
            if c["evidence"] == ["src/app.py"]:
                c["evidence"] = ["app/db.py"]
            if c["id"] == "TEST-08":
                if not done:
                    c.update(outcome="needs_verification", evidence=["raw/test-results.json"])
                else:
                    c.update(outcome="verified_fail" if bad else "verified_pass", evidence=["raw/test-results.json"])
    (paths.audit / "AUDIT_COVERAGE.json").write_text(json.dumps(cov, indent=2) + "\n", encoding="utf-8")

    nd = paths.raw / "narrative"
    nd.mkdir(parents=True, exist_ok=True)
    for name in NARRATIVES:
        (nd / (name + ".md")).write_text("Narrative for %s. See AUD-001." % name, encoding="utf-8")
    return done


def test_e2e_cli_pipeline_py_fixture(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)  # uv run exports this repo's own venv
    built = dockerutil.build_scanner_image()
    assert built.exit_code == 0, built.stderr
    project = make_fixture_repo("py-app", tmp_path).resolve()
    make_real_venv(project, "pytest==8.3.3")  # the developer's prepared environment
    before = tree_hash(project, skip=("audit", ".venv"))
    p = str(project)

    assert audit.main(["readiness", "--project", p]) == 0
    assert audit.main(["discover", "--project", p]) == 0
    assert audit.main(["scan", "--project", p]) == 0
    write_context(project)
    assert audit.main(["test", "--project", p]) == 0
    assert audit.main(["test", "--project", p, "--run"]) == 0
    capsys.readouterr()

    paths = AuditPaths.for_project(project)
    leads = json.loads((paths.raw / "leads.json").read_text(encoding="utf-8"))
    test_results = json.loads((paths.raw / "test-results.json").read_text(encoding="utf-8"))
    done = _adapt_audit(paths, leads, test_results)
    assert done, "no completed test run: %s" % test_results

    assert audit.main(["validate", "--project", p]) == 0, capsys.readouterr().out
    assert audit.main(["render", "--project", p]) == 0, capsys.readouterr().out

    report = (paths.audit / "AUDIT_REPORT.md").read_text(encoding="utf-8")
    assert (paths.audit / "REMEDIATION_PLAN.md").is_file()
    digest = dockerutil.image_digest(dockerutil.SCANNER_IMAGE)
    assert digest and digest in report
    assert "| Test environment | developer's machine (local environment); runtimes: Python " in report
    for r in done:
        c = r["counts"]
        assert "%d / %d / %d / %d" % (c["passed"], c["failed"], c["errors"], c["skipped"]) in report
    assert "AUD-001" in report and "{{" not in report
    assert tree_hash(project, skip=("audit", ".venv")) == before
