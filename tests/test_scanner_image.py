import json
import sys
from pathlib import Path

from helpers import SKILL_DIR

import pytest

sys.path.insert(0, str(SKILL_DIR / "scripts"))

from auditlib import SKILL_ROOT, dockerutil  # noqa: E402

pytestmark = pytest.mark.docker


def _tool_checks(v):
    """(tool, argv, expected version) for all 12 scanners."""
    b = {k: x["version"] for k, x in v["binaries"].items()}
    p = v["pip"]
    return [
        ("osv-scanner", ["osv-scanner", "--version"], b["osv-scanner"]),
        ("gitleaks", ["gitleaks", "version"], b["gitleaks"]),
        ("hadolint", ["hadolint", "--version"], b["hadolint"]),
        ("actionlint", ["actionlint", "-version"], b["actionlint"]),
        ("trivy", ["trivy", "--version"], "Version: %s" % b["trivy"]),
        ("semgrep", ["semgrep", "--version"], p["semgrep"]),
        ("bandit", ["bandit", "--version"], p["bandit"]),
        ("checkov", ["checkov", "--version"], p["checkov"]),
        ("ruff", ["ruff", "--version"], p["ruff"]),
        ("lizard", ["lizard", "--version"], p["lizard"]),
        ("zizmor", ["zizmor", "--version"], p["zizmor"]),
        ("jscpd", ["jscpd", "--version"], v["npm"]["jscpd"]),
    ]


def test_scanner_image_builds_and_tools_report_versions(tmp_path):
    from auditlib.paths import AuditPaths
    built = dockerutil.build_scanner_image(force=True)
    assert built.exit_code == 0, built.stderr[-3000:]
    assert dockerutil.image_exists(dockerutil.SCANNER_IMAGE)
    assert dockerutil.image_digest(dockerutil.SCANNER_IMAGE)

    v = json.loads((SKILL_ROOT / "assets" / "tool-versions.json").read_text(encoding="utf-8"))
    paths = AuditPaths.for_project(tmp_path)
    dockerutil.ensure_scanner_out(paths)
    checks = _tool_checks(v)
    assert len(checks) == 12
    for tool, argv, expected in checks:
        r = dockerutil.run(dockerutil.scanner_run_argv(paths, argv), timeout=180)
        out = r.stdout + r.stderr
        assert r.exit_code == 0, (tool, out)
        assert expected in out, (tool, expected, out)

    r = dockerutil.run(dockerutil.scanner_run_argv(
        paths, ["sh", "-c", "ls /rules && cat /rules/SNAPSHOT && id -u && pwd && git config --system safe.directory"]),
        timeout=60)
    assert r.exit_code == 0, r.stderr
    for pack in v["semgrep_packs"]:
        assert pack.replace("/", "-") + ".yml" in r.stdout
    assert "10001" in r.stdout and "/src" in r.stdout and "*" in r.stdout
