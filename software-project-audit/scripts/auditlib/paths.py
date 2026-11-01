"""Audit output locations and rotation of previous runs."""
from __future__ import annotations

import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class AuditPaths:
    project: Path
    audit: Path
    raw: Path

    @classmethod
    def for_project(cls, project: Path) -> "AuditPaths":
        project = Path(project)
        audit = project / "audit"
        return cls(project=project, audit=audit, raw=audit / "raw")

    def rotate(self, now: datetime | None = None) -> Path | None:
        """Move existing audit output into audit/history/<UTC stamp>/, then recreate raw/."""
        moved = None
        if self.audit.is_dir():
            children = [c for c in self.audit.iterdir() if c.name != "history"]
            if children:
                now = now or datetime.now(timezone.utc)
                if now.tzinfo is not None:
                    now = now.astimezone(timezone.utc)
                base = self.audit / "history" / now.strftime("%Y%m%dT%H%M%SZ")
                dest = base
                n = 1
                while dest.exists():
                    n += 1
                    dest = base.with_name("%s-%d" % (base.name, n))
                dest.mkdir(parents=True)
                for c in children:
                    shutil.move(str(c), str(dest / c.name))
                moved = dest
        self.raw.mkdir(parents=True, exist_ok=True)
        return moved
