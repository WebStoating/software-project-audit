from datetime import datetime, timezone

from auditlib.paths import AuditPaths


def test_rotate_preserves_each_previous_run(tmp_path):
    p = AuditPaths.for_project(tmp_path)
    p.raw.mkdir(parents=True)
    (p.audit / "AUDIT_REPORT.md").write_text("edit1")
    t1 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 1, 2, 11, 30, 5, tzinfo=timezone.utc)
    h1 = p.rotate(t1)
    assert h1 == p.audit / "history" / "20260101T100000Z"
    (p.audit / "AUDIT_REPORT.md").write_text("edit2")
    h2 = p.rotate(t2)
    assert (h1 / "AUDIT_REPORT.md").read_text() == "edit1"
    assert (h2 / "AUDIT_REPORT.md").read_text() == "edit2"
    assert (h2 / "raw").is_dir()
    assert p.raw.is_dir() and list(p.raw.iterdir()) == []
    assert not (p.audit / "AUDIT_REPORT.md").exists()


def test_rotate_noop_on_fresh_project(tmp_path):
    p = AuditPaths.for_project(tmp_path)
    assert p.rotate() is None
    assert p.raw.is_dir()


def test_rotate_same_second_does_not_clobber(tmp_path):
    p = AuditPaths.for_project(tmp_path)
    now = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    p.audit.mkdir()
    (p.audit / "r.md").write_text("one")
    h1 = p.rotate(now)
    (p.audit / "r.md").write_text("two")
    h2 = p.rotate(now)
    (p.audit / "r.md").write_text("three")
    h3 = p.rotate(now)
    assert len({h1, h2, h3}) == 3
    assert [(h / "r.md").read_text() for h in (h1, h2, h3)] == ["one", "two", "three"]
    assert h2.name == h1.name + "-2" and h3.name == h1.name + "-3"
