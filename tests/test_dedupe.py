import sys
from pathlib import Path

from helpers import SKILL_DIR

sys.path.insert(0, str(SKILL_DIR / "scripts"))

from auditlib import parsers  # noqa: E402
from auditlib.dedupe import dedupe  # noqa: E402
from auditlib.models import Lead  # noqa: E402


def _leads():
    return [
        Lead("bandit", "B608", "Possible SQL injection", "app/db.py", 12, 12, "Medium", ["CWE-89"]),
        Lead("semgrep", "sqli.rule", "SQL injection via f-string", "app/db.py", 12, 13, "High",
             ["CWE-89", "CWE-564"], ["A05:2025"]),
        Lead("gitleaks", "generic-api-key", "Generic API key", "app/config.py", 1, 1, "High"),
        Lead("ruff", "F401", "unused import", "app/db.py", 12, 12),
        Lead("osv-scanner", "GHSA-1", "requests vuln", "requirements.txt", None, None, "High", ["CWE-400"],
             extra={"package": "requests"}),
        Lead("osv-scanner", "GHSA-1", "urllib3 vuln", "requirements.txt", None, None, "High", ["CWE-400"],
             extra={"package": "urllib3"}),
    ]


def test_dedupe_merges_semgrep_and_bandit_same_line():
    out = dedupe(_leads())
    merged = [r for r in out if set(r["tools"]) == {"bandit", "semgrep"}]
    assert len(merged) == 1
    rec = merged[0]
    assert rec["path"] == "app/db.py" and rec["start_line"] == 12 and rec["end_line"] == 13
    assert sorted(rec["rule_ids"]) == ["B608", "sqli.rule"]
    assert rec["cwe"] == ["CWE-564", "CWE-89"] or sorted(rec["cwe"]) == ["CWE-564", "CWE-89"]
    assert rec["severity_hint"] == "High"
    assert rec["owasp"] == ["A05:2025"]


def test_dedupe_does_not_merge_without_cwe_overlap():
    out = dedupe(_leads())
    ruff = [r for r in out if r["tools"] == ["ruff"]]
    assert len(ruff) == 1  # same line, no CWE overlap


def test_dedupe_does_not_merge_lockfile_leads_by_missing_line():
    out = dedupe(_leads())
    osv = [r for r in out if r["tools"] == ["osv-scanner"]]
    assert len(osv) == 2


def test_dedupe_same_fingerprint_merges():
    a = Lead("gitleaks", "generic-api-key", "k", "a.py", 3, 3)
    b = Lead("gitleaks", "generic-api-key", "k again", "a.py", 3, 3)
    out = dedupe([a, b])
    assert len(out) == 1 and out[0]["tools"] == ["gitleaks"]


def test_dedupe_ids_deterministic():
    leads = _leads()
    first = dedupe(leads)
    second = dedupe(list(reversed(leads)))
    assert first == second
    assert [r["id"] for r in first] == ["L-%04d" % i for i in range(1, len(first) + 1)]
    keys = [(r["path"] or "", r["start_line"] or 0) for r in first]
    assert keys == sorted(keys)


def test_dedupe_empty():
    assert dedupe([]) == []


DATA = Path(__file__).resolve().parent / "data" / "scanner-output"


def test_trivy_osv_same_advisory_dedupes():
    osv = Lead("osv-scanner", "PYSEC-2018-28", "requests 2.19.1: x", "requirements.txt", None, None, "High",
               extra={"package": "requests", "ids": ["PYSEC-2018-28", "GHSA-x84v-xcm2-53pg"],
                      "aliases": ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg", "PYSEC-2018-28"]})
    trivy = Lead("trivy", "CVE-2018-18074", "requests 2.19.1: y", "requirements.txt", None, None, "High",
                 ["CWE-522"], extra={"package": "requests", "vuln_id": "CVE-2018-18074",
                                     "aliases": ["GHSA-x84v-xcm2-53pg"]})
    other_pkg = Lead("trivy", "CVE-2018-18074", "urllib3: z", "requirements.txt", None, None, "High",
                     extra={"package": "urllib3", "vuln_id": "CVE-2018-18074"})
    other_file = Lead("trivy", "CVE-2018-18074", "requests: w", "sub/requirements.txt", None, None, "High",
                      extra={"package": "requests", "vuln_id": "CVE-2018-18074"})
    out = dedupe([osv, trivy, other_pkg, other_file])
    assert len(out) == 3
    (merged,) = [r for r in out if len(r["tools"]) == 2]
    assert merged["tools"] == ["osv-scanner", "trivy"] and merged["path"] == "requirements.txt"
    assert sorted(merged["rule_ids"]) == ["CVE-2018-18074", "PYSEC-2018-28"]
    assert merged["cwe"] == ["CWE-522"]


def test_trivy_osv_recorded_samples_merge_shared_advisories():
    leads = parsers.parse_osv(DATA / "osv.json") + parsers.parse_trivy(DATA / "trivy.json")
    requests = [r for r in dedupe(leads) if r["extra"].get("package") == "requests"]
    # OSV reports 3 requests advisories, Trivy 5; the 3 shared ones merge.
    assert len(requests) == 5
    assert sum(1 for r in requests if set(r["tools"]) == {"osv-scanner", "trivy"}) == 3
