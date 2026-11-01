import re
from pathlib import Path

import pytest

from helpers import FORBIDDEN_TOOL_NAMES as FORBIDDEN


def parse_frontmatter(text):
    m = re.match(r"---\n(.*?)\n---\n", text, re.S)
    assert m, "missing frontmatter"
    data = {}
    for line in m.group(1).splitlines():
        if not line.strip() or line.startswith((" ", "\t")) or ":" not in line:
            continue
        k, v = line.split(":", 1)
        data[k.strip()] = v.strip().strip('"')
    return data


def skill_md(skill_root):
    return (skill_root / "SKILL.md").read_text(encoding="utf-8")


def test_frontmatter_name_matches_folder(skill_root):
    fm = parse_frontmatter(skill_md(skill_root))
    assert fm["name"] == skill_root.name == "audit"


def test_description_and_compatibility_limits(skill_root):
    fm = parse_frontmatter(skill_md(skill_root))
    assert 0 < len(fm["description"]) <= 1024
    assert len(fm["compatibility"]) <= 500


def test_skill_md_under_500_lines(skill_root):
    assert len(skill_md(skill_root).splitlines()) < 500


def test_no_agent_specific_tool_names(skill_root):
    files = [skill_root / "SKILL.md"] + sorted((skill_root / "references").glob("*.md"))
    for f in files:
        text = f.read_text(encoding="utf-8")
        for bad in FORBIDDEN:
            assert bad not in text, f"{bad} in {f}"


def test_cli_lists_subcommands(capsys):
    import audit

    with pytest.raises(SystemExit) as e:
        audit.main(["--help"])
    assert e.value.code == 0
    out = capsys.readouterr().out
    for name in ["readiness", "discover", "scan", "test", "validate", "render"]:
        assert name in out


def test_skill_version_read_from_frontmatter():
    import auditlib

    assert auditlib.SKILL_VERSION == "1.0.0"
    assert (auditlib.SKILL_ROOT / "SKILL.md").is_file()
