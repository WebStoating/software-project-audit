"""Run ledger: raw/run-ledger.json, a JSON array of RunRecord dicts."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Callable

from .models import RunRecord

LEDGER_NAME = "run-ledger.json"
_replace = os.replace  # bound once, so tests patching os.replace elsewhere do not reach the ledger


def load_runs(raw: Path) -> list[RunRecord]:
    p = Path(raw) / LEDGER_NAME
    if not p.is_file():
        return []
    return [RunRecord(**d) for d in json.loads(p.read_text(encoding="utf-8"))]


def _write_runs(raw: Path, runs: list) -> None:
    """Write the ledger atomically: a temp file in the same folder, then os.replace."""
    fd, tmp = tempfile.mkstemp(prefix=".%s." % LEDGER_NAME, suffix=".tmp", dir=str(raw))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(runs, indent=2) + "\n")
        _replace(tmp, str(raw / LEDGER_NAME))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def append_run(raw: Path, rec: RunRecord) -> None:
    raw = Path(raw)
    raw.mkdir(parents=True, exist_ok=True)
    runs = [r.to_dict() for r in load_runs(raw)]
    runs.append(rec.to_dict())
    _write_runs(raw, runs)


def replace_runs(raw: Path, keep: Callable[[dict], bool]) -> int:
    """Drop every ledger record for which keep(record_dict) is false; return how many were dropped."""
    raw = Path(raw)
    if not (raw / LEDGER_NAME).is_file():
        return 0
    runs = [r.to_dict() for r in load_runs(raw)]
    kept = [r for r in runs if keep(r)]
    if len(kept) != len(runs):
        _write_runs(raw, kept)
    return len(runs) - len(kept)
