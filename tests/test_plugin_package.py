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


DEV_CATALOG = PLUGIN_DIR.parent / ".agents" / "plugins" / "marketplace.json"
DEV_MARKETPLACE = "software-project-audit-dev"


def test_install_script_is_gone():
    assert not (PLUGIN_DIR.parent / "install.sh").exists(), "install via the plugin, not a symlink"


def test_dev_catalog_points_at_local_plugin():
    cat = json.loads(DEV_CATALOG.read_text(encoding="utf-8"))
    assert cat["name"] == DEV_MARKETPLACE
    (entry,) = cat["plugins"]
    assert entry["name"] == NAME
    assert entry["source"] == {"source": "local", "path": "./software-project-audit"}
    assert entry["policy"]["installation"] and entry["policy"]["authentication"] and entry["category"]


@pytest.mark.agentcli
@pytest.mark.skipif(shutil.which("codex") is None, reason="codex CLI not installed")
def test_codex_installs_only_the_plugin_folder(tmp_path):
    env = {"CODEX_HOME": str(tmp_path), "HOME": str(tmp_path), "PATH": os.environ.get("PATH", "")}

    def codex(*args):
        res = subprocess.run(["codex", "plugin", *args], env=env, capture_output=True, text=True, timeout=120)
        assert res.returncode == 0, res.stdout + res.stderr

    codex("marketplace", "add", str(PLUGIN_DIR.parent))
    codex("add", "%s@%s" % (NAME, DEV_MARKETPLACE))
    installed = tmp_path / "plugins" / "cache" / DEV_MARKETPLACE / NAME
    (version_dir,) = list(installed.iterdir())
    names = {p.name for p in version_dir.iterdir()}
    assert names <= {".claude-plugin", ".codex-plugin", "plugin.json", "skills"}
    assert (version_dir / "skills" / "audit" / "SKILL.md").is_file()
    assert not (version_dir / "tests").exists()


@pytest.mark.agentcli
@pytest.mark.skipif(shutil.which("claude") is None, reason="claude CLI not installed")
def test_claude_plugin_validate_strict():
    res = subprocess.run(["claude", "plugin", "validate", "--strict", str(PLUGIN_DIR)],
                         capture_output=True, text=True, timeout=120)
    assert res.returncode == 0, res.stdout + res.stderr
