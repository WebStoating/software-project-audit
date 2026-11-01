"""Merge leads from different tools that point at the same spot."""
from __future__ import annotations

from .models import SEVERITIES, Lead


def _identity(lead: Lead) -> tuple:
    return (lead.fingerprint(), lead.extra.get("package"))


def _advisory_keys(lead: Lead) -> list:
    """One key per advisory id or alias of a dependency lead, so OSV-Scanner and Trivy reports of
    the same advisory for the same package in the same manifest merge."""
    pkg = lead.extra.get("package")
    if not pkg or lead.rule_id.startswith("license:"):
        return []
    ids = {lead.rule_id, lead.extra.get("vuln_id")}
    for k in ("ids", "aliases"):
        ids.update(lead.extra.get(k) or [])
    return [("adv", lead.path, pkg, i) for i in sorted(i for i in ids if i)]


def _sort_key(lead: Lead) -> tuple:
    return (lead.path is not None, lead.path or "", lead.start_line or 0, lead.tool, lead.rule_id,
            lead.message)


def _sev_rank(hint) -> int:
    return SEVERITIES.index(hint) if hint in SEVERITIES else len(SEVERITIES)


def _merge(group: list, ident: str) -> dict:
    first = group[0]
    best = min(group, key=lambda lead: _sev_rank(lead.severity_hint))
    tools, rule_ids, cwe, owasp = [], [], [], []
    for lead in group:
        for seq, value in ((tools, lead.tool), (rule_ids, lead.rule_id)):
            if value not in seq:
                seq.append(value)
        cwe += [c for c in lead.cwe if c not in cwe]
        owasp += [o for o in lead.owasp if o not in owasp]
    extra = {}
    for lead in group:
        for k, v in lead.extra.items():
            extra.setdefault(k, v)
    ends = [lead.end_line for lead in group if lead.end_line is not None]
    return {
        "id": ident, "tools": tools, "rule_ids": rule_ids,
        "tool": first.tool, "rule_id": first.rule_id, "message": first.message,
        "path": first.path, "start_line": first.start_line, "end_line": max(ends) if ends else None,
        "severity_hint": best.severity_hint, "cwe": sorted(cwe), "owasp": sorted(owasp),
        "extra": extra,
        "sources": [{"tool": lead.tool, "rule_id": lead.rule_id, "message": lead.message} for lead in group],
        "fingerprint": first.fingerprint(),
    }


def dedupe(leads: list) -> list:
    """Cluster leads sharing a fingerprint, a (path, package, advisory id or alias), or a (path, line)
    with an overlapping CWE.

    Output order and ids (L-0001...) follow sorted path/line order, independent of input order.
    """
    ordered = sorted(leads, key=_sort_key)
    parent = list(range(len(ordered)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    seen = {}
    for i, lead in enumerate(ordered):
        keys = [("id",) + _identity(lead)] + _advisory_keys(lead)
        if lead.path is not None and lead.start_line is not None:
            keys += [("cwe", lead.path, lead.start_line, c) for c in lead.cwe]
        for k in keys:
            if k in seen:
                parent[find(i)] = find(seen[k])
            else:
                seen[k] = i
    clusters = {}
    for i, lead in enumerate(ordered):
        clusters.setdefault(find(i), []).append(lead)
    groups = sorted(clusters.values(), key=lambda g: _sort_key(g[0]))
    return [_merge(g, "L-%04d" % n) for n, g in enumerate(groups, 1)]
