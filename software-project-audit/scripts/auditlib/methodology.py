"""Check IDs parsed from the running methodology document (references/methodology.md)."""
from __future__ import annotations

import re
from pathlib import Path

from . import SKILL_ROOT

_DOMAIN_HEADING = re.compile(r"^### (D\d{2}) —")
_OTHER_HEADING = re.compile(r"^#{1,3} ")
_CHECK_ROW = re.compile(r"^\| ([A-Z]+-\d{2}) \|")


def load_check_ids(path: Path | None = None) -> dict[str, list[str]]:
    """Domain id -> check IDs, in document order, from table rows under each `### Dnn —` heading."""
    path = Path(path) if path else SKILL_ROOT / "references" / "methodology.md"
    result: dict[str, list[str]] = {}
    current = None
    for line in path.read_text(encoding="utf-8").splitlines():
        m = _DOMAIN_HEADING.match(line)
        if m:
            current = m.group(1)
            result.setdefault(current, [])
        elif _OTHER_HEADING.match(line):
            current = None
        elif current:
            row = _CHECK_ROW.match(line)
            if row:
                result[current].append(row.group(1))
    return result


def all_check_ids() -> set[str]:
    return {c for ids in load_check_ids().values() for c in ids}
