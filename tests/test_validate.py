import json
import math
import os
import shutil
from collections import Counter

import pytest

from auditlib.validate import validate_audit
from helpers import make_valid_audit


@pytest.fixture
def audit(tmp_path):
    return make_valid_audit(tmp_path)


def edit(path, fn):
    data = json.loads(path.read_text(encoding="utf-8"))
    fn(data)  # mutates in place; the return value is ignored
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def findings(a, fn):
    edit(a.audit / "FINDINGS.json", fn)


def coverage(a, fn):
    edit(a.audit / "AUDIT_COVERAGE.json", fn)


def check(cov, cid):
    for d in cov["domains"]:
        for c in d["checks"]:
            if c["id"] == cid:
                return d, c
    raise KeyError(cid)


def only_error(a, *needles):
    errs = validate_audit(a)
    assert len(errs) == 1, errs
    for n in needles:
        assert n in errs[0], errs
    return errs[0]


def test_validate_baseline_ok(audit):
    assert validate_audit(audit) == []


def test_validate_schema(audit):
    findings(audit, lambda f: f[0].update(severity="Severe"))
    only_error(audit, "FINDINGS.json", "severity")


def test_validate_schema_coverage(audit):
    coverage(audit, lambda c: c["domains"][0].update(id="D99"))
    errs = validate_audit(audit)
    assert errs and all("AUDIT_COVERAGE.json" in e for e in errs)


def test_validate_missing_files(audit):
    (audit.audit / "FINDINGS.json").unlink()
    only_error(audit, "FINDINGS.json")


def test_validate_unique_ids(audit):
    findings(audit, lambda f: f.append(dict(f[0])))
    only_error(audit, "duplicate", "AUD-001")


def test_validate_evidence_path_exists(audit):
    findings(audit, lambda f: f[0]["evidence"][0].update(path="src/missing.py"))
    only_error(audit, "src/missing.py")


def test_validate_evidence_line_within_file(audit):
    findings(audit, lambda f: f[0]["evidence"][0].update(line=99))
    only_error(audit, "src/app.py", "99")


def test_validate_evidence_path_escape(audit, tmp_path):
    (tmp_path / "outside.txt").write_text("x\n")
    findings(audit, lambda f: f[0]["evidence"][0].update(path="../outside.txt", line=1))
    only_error(audit, "../outside.txt", "outside")


def test_validate_evidence_path_absolute(audit, tmp_path):
    inside = str((audit.project / "src" / "app.py").resolve())
    findings(audit, lambda f: f[0]["evidence"][0].update(path=inside, line=1))
    only_error(audit, "absolute")


def test_validate_evidence_path_symlink_escape(audit, tmp_path):
    (tmp_path / "secret.txt").write_text("x\n")
    try:
        os.symlink(tmp_path / "secret.txt", audit.project / "link.txt")
    except OSError:
        pytest.skip("symlinks unavailable")
    findings(audit, lambda f: f[0]["evidence"][0].update(path="link.txt", line=1))
    only_error(audit, "link.txt", "outside")


def test_validate_tool_ref(audit):
    findings(audit, lambda f: f[0]["evidence"][0].update(tool_ref="L-9999"))
    only_error(audit, "L-9999")


def test_validate_finding_tool_refs(audit):
    findings(audit, lambda f: f[0].update(tool_refs=["L-0001", "ruff"]))
    assert validate_audit(audit) == []
    findings(audit, lambda f: f[0].update(tool_refs=["L-0001", "nope-tool"]))
    only_error(audit, "AUD-001", "nope-tool")


def test_validate_coverage_has_every_domain(audit):
    coverage(audit, lambda c: c["domains"].pop())
    only_error(audit, "D11")


def test_validate_coverage_lists_every_check(audit):
    def drop(c):
        c["domains"][2]["checks"] = [k for k in c["domains"][2]["checks"] if k["id"] != "SEC-05"]
    coverage(audit, drop)
    only_error(audit, "SEC-05", "D03")


def test_validate_not_applicable_domain_needs_no_checks(audit):
    def na(c):
        c["domains"][8].update(applicable=False, maturity="Not applicable", reason="no runtime", checks=[])
    coverage(audit, na)
    assert validate_audit(audit) == []


def test_validate_unknown_check_id(audit):
    coverage(audit, lambda c: c["domains"][2]["checks"].append({"id": "ZZZ-99", "outcome": "not_reviewed"}))
    only_error(audit, "ZZZ-99")


def test_validate_verified_needs_evidence(audit):
    coverage(audit, lambda c: check(c, "SEC-03")[1].update(evidence=[]))
    only_error(audit, "SEC-03", "evidence")


def test_validate_standards_ids_exact(audit):
    coverage(audit, lambda c: c["standards"]["owasp"].pop())
    only_error(audit, "owasp", "A10:2025")


def test_validate_standards_cwe_ids_exact(audit):
    coverage(audit, lambda c: c["standards"]["cwe"].append({"id": "CWE-1", "outcome": "not_reviewed"}))
    only_error(audit, "cwe", "CWE-1")


def test_validate_finding_listed_in_standard(audit):
    def unlist(c):
        for o in c["standards"]["owasp"]:
            o.pop("findings", None)
    coverage(audit, unlist)
    only_error(audit, "AUD-001", "A05:2025")


def test_validate_standard_findings_back_reference(audit):
    findings(audit, lambda f: f[0].update(standards_refs={"cwe": ["CWE-89"]}))
    only_error(audit, "AUD-001", "A05:2025")


def test_validate_cwe_cross_reference(audit):
    findings(audit, lambda f: f[0].update(standards_refs={"owasp": ["A05:2025"]}))
    only_error(audit, "AUD-001", "CWE-89")


def test_validate_standard_lists_unknown_finding(audit):
    coverage(audit, lambda c: c["standards"]["cwe"][0].update(findings=["AUD-777"]))
    only_error(audit, "AUD-777")


def test_validate_maturity_needs_reviewed_check(audit):
    def blank(c):
        for k in c["domains"][4]["checks"]:
            k.update(outcome="not_reviewed")
            k.pop("evidence", None)
    coverage(audit, blank)
    only_error(audit, "D05", "maturity")


def test_validate_test08_failures(audit):
    edit(audit.raw / "test-results.json", lambda r: r["results"][0]["counts"].update(failed=1))
    only_error(audit, "TEST-08")


def test_validate_test08_errors_count_as_failures(audit):
    edit(audit.raw / "test-results.json", lambda r: r["results"][0]["counts"].update(errors=2))
    only_error(audit, "TEST-08")


def test_validate_test08_needs_completed_result(audit):
    edit(audit.raw / "test-results.json", lambda r: r["results"][0].update(status="failed", counts=None))
    only_error(audit, "TEST-08")


def test_validate_test08_verified_fail_needs_failures(audit):
    coverage(audit, lambda c: check(c, "TEST-08")[1].update(outcome="verified_fail"))
    only_error(audit, "TEST-08", "verified_fail")


def test_validate_test08_verified_fail_ok_with_failures(audit):
    edit(audit.raw / "test-results.json", lambda r: r["results"][0]["counts"].update(failed=2))
    coverage(audit, lambda c: check(c, "TEST-08")[1].update(outcome="verified_fail"))
    assert validate_audit(audit) == []


def test_validate_test08_without_results_file(audit):
    (audit.raw / "test-results.json").unlink()
    only_error(audit, "TEST-08")


def test_validate_workflow_findings_exist(audit):
    coverage(audit, lambda c: c["workflows"][0].update(findings=["AUD-404"]))
    only_error(audit, "AUD-404")


def test_validate_p0_severity(audit):
    findings(audit, lambda f: f[1].update(priority="P0"))
    only_error(audit, "AUD-002", "P0")


def test_validate_p0_with_root_cause_ok(audit):
    findings(audit, lambda f: f[1].update(priority="P0", root_cause="Blocks the release because X."))
    assert validate_audit(audit) == []


def _planted_secret():
    chars = "aB3xQ9zK2mP7vL5nR8tY4wC6"
    return "".join(chars[(i * 7) % len(chars)] for i in range(40))


def test_planted_secret_has_high_entropy():
    s = _planted_secret()
    n = len(s)
    assert -sum(c / n * math.log2(c / n) for c in Counter(s).values()) > 3.5


def test_validate_secret_in_markdown(audit):
    secret = _planted_secret()
    (audit.audit / "AUDIT_REPORT.md").write_text('api_key = "%s"\n' % secret, encoding="utf-8")
    msg = only_error(audit, "AUDIT_REPORT.md")
    assert secret not in msg


def test_validate_secret_in_findings_json(audit):
    secret = _planted_secret()
    findings(audit, lambda f: f[1].update(impact='password: "%s"' % secret))
    msg = only_error(audit, "FINDINGS.json")
    assert secret not in msg


def test_validate_secret_scan_ignores_history(audit):
    hist = audit.audit / "history" / "20260101T000000Z"
    hist.mkdir(parents=True)
    (hist / "old.md").write_text('api_key = "%s"\n' % _planted_secret(), encoding="utf-8")
    assert validate_audit(audit) == []


def test_validate_context(audit):
    edit(audit.raw / "context.json", lambda c: c.pop("model_provider"))
    only_error(audit, "context.json", "model_provider")


def test_validate_context_empty_goal(audit):
    edit(audit.raw / "context.json", lambda c: c.update(goal=" "))
    only_error(audit, "context.json", "goal")


@pytest.mark.parametrize("value", [None, "yes", 1])
def test_validate_context_consent_must_be_boolean(audit, value):
    edit(audit.raw / "context.json", lambda c: c.pop("test_run_consent") if value is None else c.update(test_run_consent=value))
    only_error(audit, "context.json", "test_run_consent")


def _declined(a):
    edit(a.raw / "context.json", lambda c: c.update(test_run_consent=False))
    (a.raw / "test-results.json").unlink()
    coverage(a, lambda c: check(c, "TEST-08")[1].update(outcome="not_reviewed", evidence=[]))


def test_validate_declined_run_ok(audit):
    _declined(audit)
    assert validate_audit(audit) == []


def test_validate_declined_but_tests_ran(audit):
    _declined(audit)
    (audit.raw / "test-results.json").write_text('{"plans": [], "skipped": [], "results": []}', encoding="utf-8")
    only_error(audit, "test-results.json", "declined")


def test_validate_declined_needs_test08_not_reviewed(audit):
    _declined(audit)
    coverage(audit, lambda c: check(c, "TEST-08")[1].update(outcome="needs_verification"))
    only_error(audit, "TEST-08", "not_reviewed")


def test_validate_context_missing(audit):
    (audit.raw / "context.json").unlink()
    only_error(audit, "context.json")


def test_cli_validate_ok_and_failure(audit, capsys):
    import audit as cli  # scripts/audit.py is on sys.path via pyproject
    assert cli.main(["validate", "--project", str(audit.project)]) == 0
    assert capsys.readouterr().out.strip() == "OK"
    findings(audit, lambda f: f.append(dict(f[0])))
    assert cli.main(["validate", "--project", str(audit.project)]) == 1
    assert "AUD-001" in capsys.readouterr().out
