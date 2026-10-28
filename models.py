"""Data model shared by scanners, review, and report stages."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

CATEGORIES = ("breach", "broker", "social_search")
CATEGORY_LABELS = {
    "breach": "Breach exposure",
    "broker": "Data broker exposure",
    "social_search": "Social & search exposure",
}


@dataclass
class Subject:
    full_name: str
    emails: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    city: str = ""
    state: str = ""
    consent_attested: bool = False
    consent_ref: str = ""  # e.g. signed engagement form id

    @classmethod
    def load(cls, path: str | Path) -> "Subject":
        return cls(**json.loads(Path(path).read_text()))


@dataclass
class Finding:
    id: str
    category: str
    source: str
    title: str
    detail: str
    severity: int  # 1 (informational) .. 5 (critical)
    recommendation: str
    evidence: str = ""
    status: str = "pending"  # pending | approved | rejected
    analyst_note: str = ""


@dataclass
class Run:
    subject: Subject
    findings: list[Finding]
    scanned_at: str
    mode: str  # "live" | "demo"
    analyst: str = ""
    reviewed_at: str = ""
    scan_notes: list[str] = field(default_factory=list)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(asdict(self), indent=2))

    @classmethod
    def load(cls, path: str | Path) -> "Run":
        raw = json.loads(Path(path).read_text())
        raw["subject"] = Subject(**raw["subject"])
        raw["findings"] = [Finding(**f) for f in raw["findings"]]
        return cls(**raw)
