from pathlib import Path

import pytest

from auditlib import coverage_parse as cp

DATA = Path(__file__).resolve().parent / "data" / "test-output"


def test_parse_pytest_junit():
    assert cp.parse_junit(DATA / "pytest-junit.xml") == {"passed": 2, "failed": 1, "skipped": 1, "errors": 1}


def test_parse_vitest_junit():
    assert cp.parse_junit(DATA / "vitest-junit.xml") == {"passed": 1, "failed": 1, "skipped": 1, "errors": 0}


def test_parse_junit_rejects_entity_declarations(tmp_path):
    bomb = tmp_path / "junit.xml"
    bomb.write_text('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><testsuite><testcase name="&a;"/></testsuite>')
    with pytest.raises(ValueError):
        cp.parse_junit(bomb)


def test_parse_jest_json():
    assert cp.parse_jest_json(DATA / "jest.json") == {"passed": 1, "failed": 1, "skipped": 2, "errors": 1}


def test_parse_coveragepy_with_branches():
    assert cp.parse_coveragepy(DATA / "coveragepy.json") == {"line_pct": pytest.approx(89.47, abs=0.01),
                                                              "branch_pct": 100.0, "files": 2}


def test_parse_coveragepy_without_branches():
    r = cp.parse_coveragepy(DATA / "coveragepy-nobranch.json")
    assert r == {"line_pct": 70.0, "branch_pct": None, "files": 6}
    assert isinstance(r["line_pct"], float)


def test_parse_istanbul_summary():
    assert cp.parse_istanbul_summary(DATA / "istanbul-summary.json") == {"line_pct": 33.33, "branch_pct": 33.33, "files": 3}


def test_parse_istanbul_unknown_pct_is_an_error(tmp_path):
    p = tmp_path / "s.json"
    p.write_text('{"total": {"lines": {"total": 0, "covered": 0, "skipped": 0, "pct": "Unknown"}, "branches": {"total": 0, "covered": 0, "skipped": 0, "pct": "Unknown"}}}')
    with pytest.raises(ValueError):
        cp.parse_istanbul_summary(p)
