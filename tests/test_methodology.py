import re
import shutil
from pathlib import Path

from auditlib import SKILL_ROOT
from auditlib.methodology import all_check_ids, load_check_ids

DOCS = SKILL_ROOT / "references" / "methodology.md"


def test_load_check_ids_counts():
    ids = load_check_ids()
    assert list(ids) == ["D%02d" % i for i in range(1, 12)]
    assert ids["D01"] == ["ARC-%02d" % i for i in range(1, 16)]
    rows = re.findall(r"^\| ([A-Z]+-\d{2}) \|", DOCS.read_text(encoding="utf-8"), re.M)
    assert sum(len(v) for v in ids.values()) == len(rows)
    assert all_check_ids() == set(rows)


def test_load_check_ids_follows_running_document(tmp_path):
    copy = tmp_path / "methodology.md"
    shutil.copy(SKILL_ROOT / "references" / "methodology.md", copy)
    text = copy.read_text(encoding="utf-8")
    marker = "\n### D04 "
    assert marker in text
    head, tail = text.split(marker, 1)
    copy.write_text(head.rstrip("\n") + "\n| SEC-99 | x |\n" + marker + tail, encoding="utf-8")
    assert load_check_ids(copy)["D03"][-1] == "SEC-99"
    assert "SEC-99" not in load_check_ids()["D03"]
