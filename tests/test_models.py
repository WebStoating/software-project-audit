import pytest

from auditlib.ledger import append_run, load_runs
from auditlib.models import DOMAINS, Lead, RunRecord


def _rec(status="completed"):
    return RunRecord("semgrep", "1.0", ["semgrep"], "2026-01-01T00:00:00Z", 1.5, 0, status, None, None, {"n": 2})


def test_runrecord_rejects_unknown_status():
    with pytest.raises(ValueError):
        _rec("bogus")


def _lead(path="a.py"):
    return Lead("semgrep", "r1", "m", path, 3, 3, None, [], [], {})


def test_lead_fingerprint_stable_and_rule_sensitive():
    assert _lead().fingerprint() == _lead().fingerprint()
    assert _lead().fingerprint() != _lead("b.py").fingerprint()
    assert _lead().to_dict()["rule_id"] == "r1"


def test_domains():
    assert len(DOMAINS) == 11 and DOMAINS["D03"] == "Security and privacy"


def test_ledger_roundtrip(tmp_path):
    assert load_runs(tmp_path) == []
    append_run(tmp_path, _rec())
    append_run(tmp_path, _rec("failed"))
    runs = load_runs(tmp_path)
    assert [r.status for r in runs] == ["completed", "failed"]
    assert runs[0] == _rec()
