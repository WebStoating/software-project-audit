import json
import re

import pytest

from auditlib import render
from helpers import make_valid_audit

NARRATIVES = ["executive_summary", "architecture", "domain_assessments", "testing_confidence",
              "conclusions", "remediation_notes", "open_questions"]
HEADINGS = ["## 1. Executive Summary", "## 2. Scope, Inputs, and Limitations", "## 3. Architecture Overview",
            "## 4. Assessment Scorecard and Coverage", "## 5. Critical and High-Priority Findings",
            "## 6. Domain Assessments", "## 7. Testing and Operational Confidence",
            "## 7a. Security Standards Coverage", "## 8. Remediation Roadmap",
            "## 9. Conclusions and Accepted Trade-offs", "## 10. Appendix"]


@pytest.fixture(autouse=True)
def no_docker(monkeypatch):
    monkeypatch.setattr(render.dockerutil, "image_digest", lambda tag: "sha256:" + "ab" * 32)


def write_narratives(paths, **overrides):
    d = paths.raw / "narrative"
    d.mkdir(parents=True, exist_ok=True)
    for name in NARRATIVES:
        text = overrides.get(name, "Narrative for %s. See AUD-001." % name)
        if text is not None:
            (d / (name + ".md")).write_text(text, encoding="utf-8")


def set_priorities(paths, mapping):
    p = paths.audit / "FINDINGS.json"
    findings = json.loads(p.read_text(encoding="utf-8"))
    for f in findings:
        if f["id"] in mapping:
            f["priority"] = mapping[f["id"]]
    p.write_text(json.dumps(findings, indent=2), encoding="utf-8")


@pytest.fixture
def audit(tmp_path):
    paths = make_valid_audit(tmp_path)
    write_narratives(paths)
    return paths


def report(paths):
    return (paths.audit / "AUDIT_REPORT.md").read_text(encoding="utf-8")


def plan(paths):
    return (paths.audit / "REMEDIATION_PLAN.md").read_text(encoding="utf-8")


def test_render_writes_both_files_and_all_sections(audit):
    assert render.render_all(audit) == []
    text = report(audit)
    positions = [text.index("\n" + h + "\n") for h in HEADINGS]
    assert positions == sorted(positions)
    assert len(re.findall(r"^## ", text, re.M)) == 11
    assert "{{" not in text
    assert (audit.audit / "REMEDIATION_PLAN.md").is_file()
    assert "Narrative for executive_summary" in text
    assert "AUD-001" in text and "Query built from user input" in text


def test_render_refuses_when_validation_fails(audit):
    (audit.raw / "context.json").unlink()
    errors = render.render_all(audit)
    assert errors and any("context.json" in e for e in errors)
    assert not (audit.audit / "AUDIT_REPORT.md").exists()
    assert not (audit.audit / "REMEDIATION_PLAN.md").exists()


def test_missing_narrative_marked_and_errors(audit):
    (audit.raw / "narrative" / "architecture.md").unlink()
    errors = render.render_all(audit)
    assert any("architecture" in e for e in errors)
    assert "> ⚠ MISSING NARRATIVE: architecture" in report(audit)


def test_blank_narrative_counts_as_missing(audit):
    write_narratives(audit, conclusions="  \n\t\n")
    errors = render.render_all(audit)
    assert any("conclusions" in e for e in errors)
    assert "> ⚠ MISSING NARRATIVE: conclusions" in report(audit)


def test_unknown_finding_id_in_narrative_errors(audit):
    write_narratives(audit, conclusions="Also fixes AUD-099.")
    errors = render.render_all(audit)
    assert any("AUD-099" in e and "conclusions" in e for e in errors)


def test_unknown_finding_id_in_executive_summary_errors(audit):
    write_narratives(audit, executive_summary="Big risk AUD-042 and AUD-001.")
    assert any("AUD-042" in e for e in render.render_all(audit))


def test_p0_must_be_in_executive_summary(audit):
    set_priorities(audit, {"AUD-001": "P0"})
    write_narratives(audit, executive_summary="Nothing notable.")
    errors = render.render_all(audit)
    assert any("AUD-001" in e and "executive_summary" in e for e in errors)
    write_narratives(audit)
    assert render.render_all(audit) == []


def test_remediation_grouping_by_priority(audit):
    set_priorities(audit, {"AUD-001": "P0", "AUD-002": "P2"})
    assert render.render_all(audit) == []
    text = plan(audit)
    i_imm = text.index("Immediate / blocking")
    i_near = text.index("Near-term stabilization")
    i_strat = text.index("Strategic evolution")
    assert i_imm < i_near < i_strat
    assert "AUD-001" in text[i_imm:i_near]
    assert "AUD-002" in text[i_strat:]
    assert "AUD-002" not in text[:i_strat]
    assert "Narrative for remediation_notes" in text
    for col in ("Finding", "Desired outcome", "Verification", "Dependencies", "Effort", "Priority"):
        assert col in text


def test_standards_matrix_has_10_and_25_rows(audit):
    from auditlib.standards import cwe_ids, owasp_ids

    assert render.render_all(audit) == []
    text = report(audit)
    owasp = text[text.index("OWASP Top 10:2025"):text.index("CWE Top 25")]
    cwe = text[text.index("CWE Top 25"):text.index("\n## 8.")]
    assert len(re.findall(r"^\| A\d{2}:2025 ", owasp, re.M)) == len(owasp_ids()) == 10
    assert len(re.findall(r"^\| CWE-\d+ ", cwe, re.M)) == len(cwe_ids()) == 25
    assert re.search(r"^\| A05:2025 \| Injection \| verified_fail \| manual review \| AUD-001 \|", owasp, re.M)


def test_scope_includes_network_note_and_image_digest(audit):
    assert render.render_all(audit) == []
    text = report(audit)
    assert ("Scanners and the test run had network access. Dependency vulnerability lookups sent "
            "package names and versions (no source code) to public advisory databases; no tool uploaded "
            "source code. The code was read and processed by test-agent using test-provider.") in text
    assert "sha256:" + "ab" * 32 in text
    assert "pre-release review" in text


def test_digest_not_available_without_docker(audit, monkeypatch):
    monkeypatch.setattr(render.dockerutil, "image_digest", lambda tag: None)
    assert render.render_all(audit) == []
    assert "not available" in report(audit)


def test_render_is_byte_identical(audit):
    assert render.render_all(audit) == []
    first = (report(audit), plan(audit))
    assert render.render_all(audit) == []
    assert (report(audit), plan(audit)) == first


def test_rerender_overwrites_in_place(audit):
    assert render.render_all(audit) == []
    write_narratives(audit, conclusions="Changed conclusions text.")
    assert render.render_all(audit) == []
    assert "Changed conclusions text." in report(audit)
    assert not (audit.audit / "history").exists()


def test_md_table_escapes_pipes_and_newlines():
    out = render.md_table(["A", "B"], [["x|y", "line1\nline2\r\nline3"], [None, 3]])
    lines = out.splitlines()
    assert lines[0] == "| A | B |"
    assert lines[1] == "| --- | --- |"
    assert lines[2] == "| x\\|y | line1<br>line2<br>line3 |"
    assert lines[3] == "|  | 3 |"


def test_finding_text_with_pipe_does_not_break_table(audit):
    p = audit.audit / "FINDINGS.json"
    findings = json.loads(p.read_text(encoding="utf-8"))
    findings[0]["title"] = "a | b\nc"
    p.write_text(json.dumps(findings), encoding="utf-8")
    assert render.render_all(audit) == []
    assert "a \\| b<br>c" in report(audit)


def test_cli_render_exit_codes(audit, capsys):
    import audit as cli

    assert cli.main(["render", "--project", str(audit.project)]) == 0
    (audit.raw / "narrative" / "architecture.md").unlink()
    assert cli.main(["render", "--project", str(audit.project)]) == 1
    assert "architecture" in capsys.readouterr().out


def _with_results(paths, results, skipped=()):
    (paths.raw / "test-results.json").write_text(json.dumps(
        {"plans": [], "skipped": list(skipped), "results": results}), encoding="utf-8")


def _result(**kw):
    r = {"package_path": ".", "status": "completed", "failed_phase": None, "exit_codes": {"setup": 0, "test": 0},
         "counts": {"passed": 3, "failed": 0, "errors": 0, "skipped": 0},
         "coverage": {"line_pct": 81.5, "branch_pct": 60.0, "files": 4}, "raw_dir": "audit/raw/tests/root",
         "notes": [], "runtime_version": "Python 3.12.4", "stripped_env": [], "coverage_tool_suggestion": None}
    r.update(kw)
    return r


def test_scope_table_states_host_run(audit):
    _with_results(audit, [_result()])
    assert render.render_all(audit) == []
    text = report(audit)
    assert "| Test environment | developer's machine (local environment); runtimes: Python 3.12.4 |" in text
    assert "Test images" not in text


def test_scope_table_without_test_runs(audit):
    table = render.scope_table(audit, {}, {}, [], {"plans": [], "skipped": [], "results": []})
    assert "| Test environment | none (no tests were run) |" in table


def test_declined_run_is_stated_in_scope_and_testing(audit):
    table = render.scope_table(audit, {"test_run_consent": False}, {}, [], {})
    assert "| Test environment | none (the developer declined the test run; no project code was executed) |" in table
    assert render.test_results_block({}, declined=True) == (
        "The developer declined the unit-test run, so no project code was executed and no coverage was measured.")


def test_test_results_block_has_runtime_and_notes(audit):
    _with_results(audit, [_result(notes=["tests modified the working tree: created.db"])])
    assert render.render_all(audit) == []
    text = report(audit)
    assert "| Package | Runtime | Status | Passed / failed / errors / skipped | Line coverage |" in text
    assert "| . | Python 3.12.4 | completed | 3 / 0 / 0 / 0 | 81.5% |" in text
    assert "- `.`: tests modified the working tree: created.db" in text


def test_coverage_tool_suggestions_rendered_in_report_and_plan(audit):
    msg = "Add pytest-cov to your dev dependencies so coverage can be measured locally and in CI: `uv add --dev pytest-cov`"
    _with_results(audit, [_result(coverage_tool_suggestion=msg)])
    assert render.render_all(audit) == []
    testing = report(audit)[report(audit).index("## 7. Testing"):report(audit).index("## 7a.")]
    assert msg in testing
    remediation = plan(audit)
    assert "## Developer actions" in remediation
    assert msg in remediation[remediation.index("## Developer actions"):remediation.index("## Notes")]


def test_no_suggestions_renders_none_needed(audit):
    _with_results(audit, [_result()])
    assert render.render_all(audit) == []
    assert "No developer actions were recorded." in plan(audit)



def test_absent_results_copy():
    assert render.test_results_block({}) == "No test results were recorded (`raw/test-results.json` is absent)."
