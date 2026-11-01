import re

from auditlib import SKILL_ROOT
from auditlib.methodology import all_check_ids
from auditlib.standards import cwe_ids, load_standards, owasp_ids

REFS = SKILL_ROOT / "references"
LABELS = ["**Python:**", "**JS/TS/Node/frontend:**", "**Scanner leads:**",
          "**Manual checks:**", "**Rolls up to:**"]


def _sections(path):
    text = path.read_text(encoding="utf-8")
    parts = re.split(r"^### ", text, flags=re.M)[1:]
    return {p.split("\n", 1)[0].split(" ", 1)[0].strip(): p for p in parts}


def test_owasp_has_ten_ordered_ids():
    assert owasp_ids() == [f"A{i:02d}:2025" for i in range(1, 11)]
    d = load_standards()["owasp_top10_2025"]
    assert d["source_url"].startswith("https://") and re.match(r"\d{4}-\d{2}-\d{2}$", d["retrieved"])


def test_cwe_has_25_unique_ranked():
    items = load_standards()["cwe_top25"]["items"]
    assert [i["rank"] for i in items] == list(range(1, 26))
    ids = cwe_ids()
    assert len(set(ids)) == 25 and all(re.match(r"^CWE-\d+$", i) for i in ids)


def test_reference_files_cover_every_item():
    assert set(owasp_ids()) == set(_sections(REFS / "owasp-top10-2025.md"))
    assert set(cwe_ids()) == set(_sections(REFS / "cwe-top25.md"))


def test_reference_entries_have_required_parts():
    known = all_check_ids()
    assert known
    for fname, ids in (("owasp-top10-2025.md", owasp_ids()), ("cwe-top25.md", cwe_ids())):
        secs = _sections(REFS / fname)
        for i in ids:
            body = secs[i]
            for label in LABELS:
                assert label in body, f"{i} lacks {label}"
            rolls = body.split("**Rolls up to:**", 1)[1]
            named = set(re.findall(r"[A-Z]+-\d{2}", rolls))
            assert named, f"{i} names no check"
            assert named - known == set(), f"{i} names unknown checks {named - known}"
