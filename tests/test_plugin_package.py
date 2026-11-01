"""The software-project-audit/ folder is a plugin for Claude Code and Codex, and the only thing that ships."""
import json
import os
import shutil
import subprocess

import pytest

from helpers import PLUGIN_DIR, SKILL_DIR

NAME = "software-project-audit"
REPO_URL = "https://github.com/WebStoating/software-project-audit"
MANIFESTS = {
    "claude": PLUGIN_DIR / ".claude-plugin" / "plugin.json",
    "codex": PLUGIN_DIR / "plugin.json",
}


def _manifest(agent):
    return json.loads(MANIFESTS[agent].read_text(encoding="utf-8"))


@pytest.mark.parametrize("agent", sorted(MANIFESTS))
def test_manifest_names_the_plugin(agent):
    m = _manifest(agent)
    assert m["name"] == NAME
    assert m["description"]
    assert m["repository"] == REPO_URL
    assert m["license"] == "Apache-2.0"


@pytest.mark.parametrize("agent", sorted(MANIFESTS))
def test_manifest_version_matches_skill_version(agent):
    import auditlib

    assert _manifest(agent)["version"] == auditlib.SKILL_VERSION


def test_skill_is_discovered_from_default_skills_dir():
    assert SKILL_DIR == PLUGIN_DIR / "skills" / "audit"
    assert (SKILL_DIR / "SKILL.md").is_file()
    assert sorted(p.name for p in (PLUGIN_DIR / "skills").iterdir()) == ["audit"]
    for agent in MANIFESTS:
        assert "skills" not in _manifest(agent), "custom skill paths are not needed"


def test_plugin_root_holds_only_what_ships():
    assert sorted(p.name for p in PLUGIN_DIR.iterdir() if p.name != "__pycache__") == [
        ".claude-plugin", "plugin.json", "skills"]


def test_no_symlink_escapes_plugin_root():
    root = PLUGIN_DIR.resolve()
    for dirpath, dirnames, filenames in os.walk(PLUGIN_DIR):
        for name in dirnames + filenames:
            p = os.path.join(dirpath, name)
            if os.path.islink(p):
                target = os.path.realpath(p)
                assert target == str(root) or target.startswith(str(root) + os.sep), p


@pytest.mark.agentcli
@pytest.mark.skipif(shutil.which("claude") is None, reason="claude CLI not installed")
def test_claude_plugin_validate_strict():
    res = subprocess.run(["claude", "plugin", "validate", "--strict", str(PLUGIN_DIR)],
                         capture_output=True, text=True, timeout=120)
    assert res.returncode == 0, res.stdout + res.stderr
