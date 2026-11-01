"""install.sh symlinks the skill into Claude Code and Codex skill dirs; tests run it against a temp HOME."""
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / "software-project-audit" / "skills" / "audit"
NAME = "software-project-audit"


def run_install(home, *args, extra_env=None):
    env = {"HOME": str(home), "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    env.update(extra_env or {})
    return subprocess.run(["bash", str(ROOT / "install.sh"), *args], env=env, capture_output=True,
                          text=True, timeout=60)


def _links(home):
    return home / ".claude" / "skills" / NAME, home / ".agents" / "skills" / NAME


def _points_at_skill(link):
    return link.is_symlink() and Path(os.readlink(link)).resolve() == SKILL.resolve()


def test_install_creates_symlinks(tmp_path):
    res = run_install(tmp_path)
    assert res.returncode == 0, res.stderr
    claude, codex = _links(tmp_path)
    assert _points_at_skill(claude) and _points_at_skill(codex)
    assert (claude / "SKILL.md").is_file()


def test_install_honours_claude_config_dir_and_flags(tmp_path):
    cfg, codex_dir = tmp_path / "cfg", tmp_path / "codex-skills"
    res = run_install(tmp_path / "home", "--codex-dir", str(codex_dir), extra_env={"CLAUDE_CONFIG_DIR": str(cfg)})
    assert res.returncode == 0, res.stderr
    assert _points_at_skill(cfg / "skills" / NAME) and _points_at_skill(codex_dir / NAME)
    assert not (tmp_path / "home" / ".claude").exists() and not (tmp_path / "home" / ".agents").exists()
    claude_dir = tmp_path / "explicit"
    res = run_install(tmp_path / "home", "--claude-dir", str(claude_dir), "--codex-dir", str(codex_dir),
                      extra_env={"CLAUDE_CONFIG_DIR": str(cfg)})
    assert res.returncode == 0, res.stderr
    assert _points_at_skill(claude_dir / NAME)


def test_install_refuses_real_directory(tmp_path):
    claude, codex = _links(tmp_path)
    claude.mkdir(parents=True)
    (claude / "SKILL.md").write_text("placeholder\n", encoding="utf-8")
    res = run_install(tmp_path)
    assert res.returncode == 1
    assert "not a symlink" in (res.stdout + res.stderr)
    assert (claude / "SKILL.md").read_text(encoding="utf-8") == "placeholder\n"
    assert not codex.exists() and not codex.is_symlink()  # nothing installed when any target conflicts


def test_install_refuses_foreign_symlink(tmp_path):
    claude, _ = _links(tmp_path)
    claude.parent.mkdir(parents=True)
    other = tmp_path / "other-skill"
    other.mkdir()
    claude.symlink_to(other)
    res = run_install(tmp_path)
    assert res.returncode == 1
    assert Path(os.readlink(claude)) == other


def test_install_idempotent(tmp_path):
    assert run_install(tmp_path).returncode == 0
    res = run_install(tmp_path)
    assert res.returncode == 0, res.stderr
    assert "already installed" in res.stdout
    for link in _links(tmp_path):
        assert _points_at_skill(link)


def test_uninstall_removes_only_symlinks(tmp_path):
    assert run_install(tmp_path).returncode == 0
    claude, codex = _links(tmp_path)
    codex.unlink()
    codex.mkdir()  # a real directory the user put there must survive
    (codex / "SKILL.md").write_text("keep\n", encoding="utf-8")
    res = run_install(tmp_path, "--uninstall")
    assert res.returncode == 0, res.stderr
    assert not claude.exists() and not claude.is_symlink()
    assert (codex / "SKILL.md").read_text(encoding="utf-8") == "keep\n"
    assert SKILL.is_dir() and (SKILL / "SKILL.md").is_file()


def test_uninstall_keeps_foreign_symlink(tmp_path):
    claude, _ = _links(tmp_path)
    claude.parent.mkdir(parents=True)
    other = tmp_path / "other-skill"
    other.mkdir()
    claude.symlink_to(other)
    res = run_install(tmp_path, "--uninstall")
    assert res.returncode == 0, res.stderr
    assert claude.is_symlink() and other.is_dir()


def test_install_rejects_unknown_option(tmp_path):
    res = run_install(tmp_path, "--bogus")
    assert res.returncode == 2
    assert not (tmp_path / ".claude").exists()


def test_install_for_one_agent_only(tmp_path):
    claude, codex = _links(tmp_path)
    res = run_install(tmp_path, "--no-codex")
    assert res.returncode == 0, res.stderr
    assert _points_at_skill(claude) and not codex.exists() and not (tmp_path / ".agents").exists()
    res = run_install(tmp_path / "h2", "--no-claude")
    assert res.returncode == 0, res.stderr
    c2, x2 = _links(tmp_path / "h2")
    assert _points_at_skill(x2) and not (tmp_path / "h2" / ".claude").exists()
    res = run_install(tmp_path, "--uninstall", "--no-claude")
    assert res.returncode == 0 and _points_at_skill(claude)


def test_install_rejects_no_claude_with_no_codex(tmp_path):
    res = run_install(tmp_path, "--no-claude", "--no-codex")
    assert res.returncode == 2
    assert not (tmp_path / ".claude").exists() and not (tmp_path / ".agents").exists()
