import json

import pytest

from auditlib import ledger
from auditlib.ledger import LEDGER_NAME, append_run, load_runs, replace_runs
from auditlib.models import RunRecord


def _rec(tool, status="completed"):
    return RunRecord(tool, "1.0", [tool], "2026-01-01T00:00:00Z", 1.0, 0, status, None, None, {})


def test_replace_runs_keeps_only_matching_records(tmp_path):
    for tool in ("semgrep", "tests:.", "ruff", "tests:web"):
        append_run(tmp_path, _rec(tool))
    removed = replace_runs(tmp_path, keep=lambda r: r["tool"].startswith("tests:"))
    assert removed == 2
    assert [r.tool for r in load_runs(tmp_path)] == ["tests:.", "tests:web"]


def test_replace_runs_without_ledger_is_noop(tmp_path):
    assert replace_runs(tmp_path, keep=lambda r: False) == 0
    assert not (tmp_path / LEDGER_NAME).exists()


def test_replace_runs_is_atomic(tmp_path, monkeypatch):
    append_run(tmp_path, _rec("semgrep"))
    before = (tmp_path / LEDGER_NAME).read_text()

    def boom(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(ledger, "_replace", boom)
    with pytest.raises(OSError):
        replace_runs(tmp_path, keep=lambda r: False)
    assert (tmp_path / LEDGER_NAME).read_text() == before
    assert [p.name for p in tmp_path.iterdir()] == [LEDGER_NAME]


def test_append_run_leaves_no_temp_files(tmp_path):
    append_run(tmp_path, _rec("semgrep"))
    append_run(tmp_path, _rec("ruff"))
    assert [p.name for p in tmp_path.iterdir()] == [LEDGER_NAME]
    assert len(json.loads((tmp_path / LEDGER_NAME).read_text())) == 2
