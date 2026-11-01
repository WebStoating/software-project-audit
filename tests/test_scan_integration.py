import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "software-project-audit" / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import audit  # noqa: E402
from auditlib import dockerutil  # noqa: E402
from auditlib.ledger import load_runs  # noqa: E402
from auditlib.paths import AuditPaths  # noqa: E402
from helpers import make_fixture_repo  # noqa: E402

pytestmark = pytest.mark.docker


def _tree_hash(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if rel.parts[0] == "audit":
            continue
        h.update(str(rel).encode())
        if p.is_file() and not p.is_symlink():
            h.update(p.read_bytes())
    return h.hexdigest()


@pytest.fixture(scope="module")
def image():
    r = dockerutil.build_scanner_image()
    assert r.exit_code == 0, r.stderr
    return dockerutil.SCANNER_IMAGE


def test_scan_end_to_end_py_fixture(tmp_path, image, capsys):
    project = make_fixture_repo("py-app", tmp_path)
    before = _tree_hash(project)
    assert audit.main(["discover", "--project", str(project)]) == 0
    assert audit.main(["scan", "--project", str(project)]) == 0
    out = capsys.readouterr().out
    assert "semgrep" in out and "completed" in out
    paths = AuditPaths.for_project(project)
    runs = load_runs(paths.raw)
    assert len(runs) == 12
    states = {r.tool: r.status for r in runs}
    assert states["bandit"] == "completed" and states["gitleaks"] == "completed"
    assert states["osv-scanner"] == "completed" and states["ruff"] == "completed"
    assert states["trivy"] == "completed"
    assert all(s in ("completed", "partial") for t, s in states.items()), states
    assert {r.tool: r for r in runs}["gitleaks"].counts["mode"] == "git"
    leads = json.loads((paths.raw / "leads.json").read_text())
    by_path = {}
    for lead in leads:
        by_path.setdefault(lead["path"], []).append(lead)
    sqli = [lead for lead in by_path["app/db.py"] if "CWE-89" in lead["cwe"]]
    assert sqli and any("semgrep" in lead["tools"] for lead in sqli)
    assert any("gitleaks" in lead["tools"] for lead in by_path["app/config.py"])
    assert any("osv-scanner" in lead["tools"] and lead["extra"].get("package") == "requests"
               for lead in by_path["requirements.txt"])
    # Trivy and OSV-Scanner report the same requests advisory: one lead, both tools
    assert any({"osv-scanner", "trivy"} <= set(lead["tools"]) and lead["extra"].get("package") == "requests"
               for lead in by_path["requirements.txt"])
    assert any("trivy" in lead["tools"] and "DS-0002" in lead["rule_ids"] for lead in by_path["Dockerfile"])
    # the clean parametrized query (find_user, line 16) must not be a lead
    assert all(not (lead["start_line"] and 15 <= lead["start_line"] <= 16) for lead in by_path["app/db.py"])
    blob = "".join(p.read_text(errors="replace") for p in paths.audit.rglob("*") if p.is_file())
    assert "q7Zk2mXv9RtB4nLp8Wd3Fj6Hc1YsGa5Ue0TxNoVi" not in blob
    assert _tree_hash(project) == before


def test_scan_non_git_folder_uses_dir_mode(tmp_path, image):
    project = make_fixture_repo("ts-app", tmp_path, git=False)
    # a host-installed dependency tree must never be scanned
    leak = project / ".venv"
    leak.mkdir()
    (leak / "config.py").write_text('api_key = "q7Zk2mXv9RtB4nLp8Wd3Fj6Hc1YsGa5Ue0TxNoVi"\n')
    assert audit.main(["discover", "--project", str(project)]) == 0
    assert audit.main(["scan", "--project", str(project)]) == 0
    runs = {r.tool: r for r in load_runs(AuditPaths.for_project(project).raw)}
    assert runs["gitleaks"].counts["mode"] == "dir" and runs["gitleaks"].status == "completed"
    assert runs["bandit"].status == "not_applicable" and runs["hadolint"].status == "not_applicable"
    leads = json.loads((AuditPaths.for_project(project).raw / "leads.json").read_text())
    assert any(lead["extra"].get("package") == "lodash" for lead in leads)
    assert any(lead["path"] == "src/View.tsx" for lead in leads)
    assert any(lead["path"] == "src/calc.ts" and "CWE-95" in lead["cwe"] and "semgrep" in lead["tools"]
               for lead in leads)
    assert not any(".venv" in (lead["path"] or "") for lead in leads)
    assert runs["trivy"].status == "completed"
    assert any(lead["rule_id"] == "license:MIT" and "trivy" in lead["tools"] for lead in leads)
    assert not [lead for lead in leads if "gitleaks" in lead["tools"]]
