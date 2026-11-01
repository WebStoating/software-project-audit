import os

from auditlib import hostenv


def test_build_env_strips_credentials_and_reports_names():
    base = {"AWS_SECRET_ACCESS_KEY": "x", "GH_TOKEN": "x", "SSH_AUTH_SOCK": "/s", "ANTHROPIC_API_KEY": "x",
            "HOME": "/home/u", "PATH": "/usr/bin"}
    env, stripped = hostenv.build_env(base, [], {})
    assert stripped == ["ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY", "GH_TOKEN", "SSH_AUTH_SOCK"]
    assert env == {"HOME": "/home/u", "PATH": "/usr/bin"}


def test_build_env_prepends_path_and_pythonpath():
    base = {"PATH": "/usr/bin" + os.pathsep + "/bin", "PYTHONPATH": "/p"}
    env, _ = hostenv.build_env(base, ["/v/bin", "/w/bin"], {"PYTHONPATH": "/tools", "CI": "true"})
    assert env["PATH"].split(os.pathsep) == ["/v/bin", "/w/bin", "/usr/bin", "/bin"]
    assert env["PYTHONPATH"].split(os.pathsep) == ["/tools", "/p"]
    assert env["CI"] == "true"


def test_build_env_without_base_path_values():
    env, _ = hostenv.build_env({}, ["/v/bin"], {"PYTHONPATH": "/tools"})
    assert env["PATH"] == "/v/bin" and env["PYTHONPATH"] == "/tools"


def test_build_env_does_not_mutate_base():
    base = {"GH_TOKEN": "x", "PATH": "/usr/bin"}
    hostenv.build_env(base, ["/v/bin"], {})
    assert base == {"GH_TOKEN": "x", "PATH": "/usr/bin"}


def test_snapshot_ignores_audit_and_excluded_dirs(tmp_path):
    (tmp_path / "src" / "audit").mkdir(parents=True)
    (tmp_path / "src" / "audit" / "x.py").write_text("a")
    for d in ("audit", ".venv", "node_modules", "pkg/node_modules"):
        (tmp_path / d).mkdir(parents=True)
    before = hostenv.snapshot(tmp_path)
    assert list(before) == ["src/audit/x.py"]
    (tmp_path / "audit" / "r.json").write_text("{}")
    (tmp_path / ".venv" / "f").write_text("x")
    (tmp_path / "pkg" / "node_modules" / "f").write_text("x")
    assert hostenv.changed_paths(before, hostenv.snapshot(tmp_path)) == []
    (tmp_path / "src" / "audit" / "x.py").write_text("changed")
    assert hostenv.changed_paths(before, hostenv.snapshot(tmp_path)) == ["src/audit/x.py"]


def test_snapshot_records_symlinks_without_following(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "f").write_text("x")
    (tmp_path / "link").symlink_to(tmp_path / "real")
    assert sorted(hostenv.snapshot(tmp_path)) == ["link", "real/f"]


def test_changed_paths_lists_added_modified_removed():
    before = {"a": (1, 1), "b": (1, 1), "c": (1, 1)}
    after = {"a": (1, 1), "b": (2, 5), "d": (1, 1)}
    assert hostenv.changed_paths(before, after) == ["b", "c", "d"]


def test_redact_handles_spaces_and_unicode(tmp_path):
    project = tmp_path / "my prø ject"
    text = "%s/.venv/bin/python and /home/u/.cache" % project
    assert hostenv.redact(text, project, "/home/u") == "<project>/.venv/bin/python and ~/.cache"


def test_redact_project_inside_home():
    assert hostenv.redact("/home/u/p/x", "/home/u/p", "/home/u") == "<project>/x"
