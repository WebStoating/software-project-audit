import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "software-project-audit" / "scripts"))

from auditlib import parsers  # noqa: E402

DATA = Path(__file__).resolve().parent / "data" / "scanner-output"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _fake_key():
    text = (FIXTURES / "py-app" / "app" / "config.py").read_text(encoding="utf-8")
    return re.search(r'"([^"]+)"', text).group(1)


def _by_path(leads):
    out = {}
    for lead in leads:
        out.setdefault(lead.path, []).append(lead)
    return out


def test_parse_semgrep():
    leads = parsers.parse_semgrep(DATA / "semgrep.json")
    assert len(leads) == 5
    by = _by_path(leads)
    assert set(by) == {".github/workflows/ci.yml", "Dockerfile", "src/View.tsx", "app/db.py", "src/calc.ts"}
    (sqli,) = by["app/db.py"]
    assert sqli.start_line == 12 and sqli.cwe == ["CWE-89"]
    (ev,) = by["src/calc.ts"]
    assert ev.start_line == 3 and ev.cwe == ["CWE-95"]
    xss = by["src/View.tsx"][0]
    assert xss.tool == "semgrep" and xss.start_line == 3
    assert xss.cwe == ["CWE-79"]
    assert xss.owasp == ["A05:2025"]
    assert xss.extra["owasp_2021"] == ["A03:2021"]
    assert xss.severity_hint == "Medium"
    docker = by["Dockerfile"][0]
    assert docker.cwe == ["CWE-250"] and docker.severity_hint == "High"
    assert all(re.fullmatch(r"A\d\d:2025", o) for lead in leads for o in lead.owasp)


def test_semgrep_owasp_2021_tags_never_enter_owasp(tmp_path):
    doc = {"results": [{
        "check_id": "r", "path": "/src/a.py", "start": {"line": 2}, "end": {"line": 2},
        "extra": {"message": "m", "severity": "INFO", "metadata": {
            "cwe": ["CWE-89: SQL Injection", "CWE-89: SQL Injection"],
            "owasp": ["A03:2021 - Injection", "A07:2017 - XSS"]}}}]}
    p = tmp_path / "s.json"
    p.write_text(json.dumps(doc))
    (lead,) = parsers.parse_semgrep(p)
    assert lead.owasp == []
    assert lead.extra["owasp_2021"] == ["A03:2021"]
    assert lead.cwe == ["CWE-89"]
    assert lead.severity_hint == "Low"


def test_parse_bandit():
    leads = parsers.parse_bandit(DATA / "bandit.json")
    assert len(leads) == 3
    sqli = [lead for lead in leads if lead.path == "app/db.py"]
    assert len(sqli) == 1
    assert sqli[0].start_line == 12 and sqli[0].rule_id == "B608"
    assert sqli[0].cwe == ["CWE-89"] and sqli[0].severity_hint == "Medium"
    assert "code" not in sqli[0].extra


def test_parse_osv():
    leads = parsers.parse_osv(DATA / "osv.json")
    packages = {lead.extra["package"] for lead in leads}
    assert packages == {"requests", "lodash"}
    by = _by_path(leads)
    assert set(by) == {"requirements.txt", "package-lock.json"}
    req = [lead for lead in leads if lead.extra["package"] == "requests"][0]
    assert req.extra["version"] == "2.19.1" and req.extra["ecosystem"] == "PyPI"
    assert req.start_line is None and req.severity_hint in ("Critical", "High", "Medium", "Low")
    assert len({(lead.extra["package"], lead.rule_id) for lead in leads}) == len(leads)


def test_parse_gitleaks():
    leads = parsers.parse_gitleaks(DATA / "gitleaks.json")
    assert len(leads) == 1
    lead = leads[0]
    assert lead.path == "app/config.py" and lead.start_line == 1
    assert lead.rule_id == "generic-api-key" and lead.severity_hint == "High"
    blob = json.dumps(lead.to_dict())
    assert "Secret" not in blob and "Match" not in blob


def test_parse_checkov():
    leads = parsers.parse_checkov(DATA / "checkov.json")
    assert len(leads) == 3
    assert {lead.rule_id for lead in leads} >= {"CKV_DOCKER_2", "CKV2_GHA_1"}
    assert {lead.path for lead in leads} == {"Dockerfile", ".github/workflows/ci.yml"}


def test_parse_checkov_single_framework_dict(tmp_path):
    doc = {"check_type": "dockerfile", "results": {"failed_checks": [{
        "check_id": "CKV_DOCKER_3", "check_name": "n", "file_abs_path": "/src/Dockerfile",
        "file_line_range": [2, 4]}]}}
    p = tmp_path / "c.json"
    p.write_text(json.dumps(doc))
    (lead,) = parsers.parse_checkov(p)
    assert (lead.start_line, lead.end_line) == (2, 4)


def test_parse_checkov_relative_fallback_path(tmp_path):
    doc = {"check_type": "dockerfile", "results": {"failed_checks": [{
        "check_id": "CKV_DOCKER_3", "check_name": "n", "file_path": "/docker/Dockerfile",
        "file_line_range": [1, 2]}]}}
    p = tmp_path / "c.json"
    p.write_text(json.dumps(doc))
    assert parsers.parse_checkov(p)[0].path == "docker/Dockerfile"


def test_parse_hadolint():
    leads = parsers.parse_hadolint(DATA / "hadolint.json")
    assert len(leads) == 1
    assert leads[0].rule_id == "DL3042" and leads[0].path == "Dockerfile" and leads[0].start_line == 4
    assert leads[0].severity_hint == "Medium"


def test_parse_zizmor():
    leads = parsers.parse_zizmor(DATA / "zizmor.json")
    assert {lead.rule_id for lead in leads} == {"artipacked", "excessive-permissions", "unpinned-uses"}
    assert {lead.path for lead in leads} == {".github/workflows/ci.yml"}
    artipacked = [lead for lead in leads if lead.rule_id == "artipacked"][0]
    assert artipacked.start_line == 7  # zizmor rows are 0-based
    unpinned = [lead for lead in leads if lead.rule_id == "unpinned-uses"][0]
    assert unpinned.severity_hint == "High"


def test_parse_actionlint():
    leads = parsers.parse_actionlint(DATA / "actionlint.json")
    assert len(leads) == 1
    assert leads[0].path == ".github/workflows/bad.yml" and leads[0].start_line == 7
    assert "snippet" not in leads[0].extra


def test_parse_actionlint_null(tmp_path):
    p = tmp_path / "a.json"
    p.write_text("null")
    assert parsers.parse_actionlint(p) == []


def test_parse_lizard_thresholds():
    leads = parsers.parse_lizard(DATA / "lizard.csv")
    assert len(leads) == 1  # only classify (CCN 17); total_a/b are CCN 3
    assert leads[0].path == "app/util.py" and leads[0].start_line == 4 and leads[0].end_line == 37
    assert leads[0].extra["ccn"] == 17 and leads[0].extra["function"] == "classify"


def test_parse_lizard_long_function(tmp_path):
    p = tmp_path / "l.csv"
    p.write_text('101,5,900,1,110,"f@1-110@/src/a.py","/src/a.py","f","f( )",1,110\n'
                 '100,15,10,1,10,"g@1-10@/src/b.py","/src/b.py","g","g( )",1,10\n')
    leads = parsers.parse_lizard(p)
    assert [lead.path for lead in leads] == ["a.py"]


def test_parse_jscpd():
    leads = parsers.parse_jscpd(DATA / "jscpd.json")
    assert len(leads) == 1
    lead = leads[0]
    assert lead.path == "app/util.py" and (lead.start_line, lead.end_line) == (40, 46)
    assert lead.extra["other_path"] == "app/util.py" and lead.extra["other_start_line"] == 49
    assert "fragment" not in lead.extra and "fragment" not in json.dumps(lead.to_dict())


def test_parse_ruff():
    leads = parsers.parse_ruff(DATA / "ruff.json")
    assert len(leads) == 1
    assert leads[0].rule_id == "F401" and leads[0].path == "app/util.py" and leads[0].start_line == 1


def test_parse_trivy():
    leads = parsers.parse_trivy(DATA / "trivy.json")
    assert len(leads) == 9 and {lead.tool for lead in leads} == {"trivy"}
    vulns = [lead for lead in leads if lead.path == "requirements.txt"]
    assert len(vulns) == 6
    assert {lead.extra["package"] for lead in vulns} == {"requests", "pytest"}
    (cve,) = [lead for lead in vulns if lead.rule_id == "CVE-2018-18074"]
    assert cve.extra["package"] == "requests" and cve.extra["installed_version"] == "2.19.1"
    assert cve.extra["fixed_version"] == "2.20.0" and cve.extra["vuln_id"] == "CVE-2018-18074"
    assert cve.extra["aliases"] == ["GHSA-x84v-xcm2-53pg"]
    assert cve.cwe == ["CWE-522"] and cve.severity_hint == "High"
    assert cve.start_line is None and cve.owasp == []
    misconf = [lead for lead in leads if lead.path == "Dockerfile"]
    assert sorted(lead.rule_id for lead in misconf) == ["DS-0002", "DS-0026"]
    root = next(lead for lead in misconf if lead.rule_id == "DS-0002")
    assert root.severity_hint == "High" and "root" in root.message
    (lic,) = [lead for lead in leads if lead.rule_id.startswith("license:")]
    assert lic.rule_id == "license:MIT" and lic.path == "package-lock.json"
    assert lic.severity_hint == "Low" and lic.extra["package"] == "lodash"
    assert lic.extra["category"] == "notice"


def test_parse_trivy_maps_unknown_severity_and_skips_passes(tmp_path):
    doc = {"SchemaVersion": 2, "Results": [
        {"Target": "requirements.txt", "Class": "lang-pkgs", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "PkgName": "a", "InstalledVersion": "1", "Severity": "UNKNOWN"}]},
        {"Target": "Dockerfile", "Class": "config", "Misconfigurations": [
            {"ID": "DS-0001", "Title": "t", "Message": "m", "Severity": "CRITICAL", "Status": "PASS"},
            {"ID": "DS-0005", "AVDID": "AVD-DS-0005", "Title": "t", "Message": "m", "Severity": "MEDIUM",
             "Status": "FAIL", "CauseMetadata": {"StartLine": 4, "EndLine": 5}}]}]}
    p = tmp_path / "t.json"
    p.write_text(json.dumps(doc))
    vuln, mis = parsers.parse_trivy(p)
    assert vuln.severity_hint is None and vuln.cwe == [] and vuln.extra["fixed_version"] is None
    assert mis.rule_id == "DS-0005" and (mis.start_line, mis.end_line) == (4, 5)
    assert mis.severity_hint == "Medium" and mis.extra["avd_id"] == "AVD-DS-0005"


def test_parse_empty_outputs(tmp_path):
    p = tmp_path / "e.json"
    p.write_text("[]")
    for fn in (parsers.parse_hadolint, parsers.parse_zizmor, parsers.parse_ruff,
               parsers.parse_gitleaks, parsers.parse_checkov, parsers.parse_actionlint):
        assert fn(p) == []
    p.write_text('{"results": []}')
    assert parsers.parse_semgrep(p) == [] and parsers.parse_bandit(p) == [] and parsers.parse_osv(p) == []
    assert parsers.parse_trivy(p) == []
    p.write_text('{"SchemaVersion": 2, "ArtifactName": "/src"}')
    assert parsers.parse_trivy(p) == []


def test_no_secret_in_leads():
    key = _fake_key()
    blob = ""
    for name, fn in (("semgrep.json", parsers.parse_semgrep), ("bandit.json", parsers.parse_bandit),
                     ("osv.json", parsers.parse_osv), ("gitleaks.json", parsers.parse_gitleaks),
                     ("checkov.json", parsers.parse_checkov), ("hadolint.json", parsers.parse_hadolint),
                     ("zizmor.json", parsers.parse_zizmor), ("actionlint.json", parsers.parse_actionlint),
                     ("lizard.csv", parsers.parse_lizard), ("jscpd.json", parsers.parse_jscpd),
                     ("ruff.json", parsers.parse_ruff), ("trivy.json", parsers.parse_trivy)):
        blob += json.dumps([lead.to_dict() for lead in fn(DATA / name)])
    assert key not in blob


def test_samples_contain_no_secret_and_gitleaks_is_redacted():
    key = _fake_key()
    for p in (Path(__file__).resolve().parent / "data").rglob("*"):
        if p.is_file():
            assert key not in p.read_text(encoding="utf-8", errors="replace"), p
    assert "REDACTED" in (DATA / "gitleaks.json").read_text(encoding="utf-8")


def test_gitleaks_parser_drops_secret_even_if_unredacted(tmp_path):
    doc = [{"RuleID": "r", "Description": "d", "StartLine": 3, "EndLine": 3, "File": "x.py",
            "Secret": "TOPSECRETVALUE", "Match": "k = TOPSECRETVALUE", "Commit": "abc"}]
    p = tmp_path / "g.json"
    p.write_text(json.dumps(doc))
    assert "TOPSECRETVALUE" not in json.dumps([lead.to_dict() for lead in parsers.parse_gitleaks(p)])
