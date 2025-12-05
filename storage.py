from dataclasses import dataclass, field
from typing import Dict, List, Optional
import uuid

import db  # new

@dataclass
class Asset:
    id: str
    name: str
    tags: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)

@dataclass
class Finding:
    id: str
    asset_name: str
    title: str
    metrics: Dict[str, str]
    score: float
    severity: str
    vector: str

class Store:
    def __init__(self) -> None:
        self.assets: Dict[str, Asset] = {}
        self.findings: Dict[str, Finding] = {}

    def _id(self) -> str:
        return uuid.uuid4().hex

    def load_from_db(self) -> None:
        db.init_db()
        self.assets.clear()
        self.findings.clear()

        for a in db.load_assets():
            self.assets[a["id"]] = Asset(id=a["id"], name=a["name"], tags=a["tags"], services=a["services"])

        for f in db.load_findings():
            self.findings[f["id"]] = Finding(
                id=f["id"],
                asset_name=f["asset_name"],
                title=f["title"],
                metrics=f["metrics"],
                score=f["score"],
                severity=f["severity"],
                vector=f["vector"],
            )

    # --- Assets ---
    def add_asset(self, name: str, tags: List[str], services: List[str]) -> Asset:
        a = Asset(id=self._id(), name=name.strip(), tags=tags, services=services)
        self.assets[a.id] = a
        db.upsert_asset(a.id, a.name, a.tags, a.services)
        return a

    def get_asset_by_name(self, name: str) -> Optional[Asset]:
        key = name.strip().lower()
        for a in self.assets.values():
            if a.name.strip().lower() == key:
                return a
        return None

    def delete_asset(self, asset_id: str) -> None:
        if asset_id in self.assets:
            db.delete_asset(asset_id)
            del self.assets[asset_id]

    # --- Findings ---
    def add_finding(
        self,
        asset_name: str,
        title: str,
        metrics: Dict[str, str],
        score: float,
        severity: str,
        vector: str,
    ) -> Finding:
        f = Finding(
            id=self._id(),
            asset_name=asset_name.strip() or "Unassigned",
            title=title.strip() or "Untitled Finding",
            metrics=metrics,
            score=score,
            severity=severity,
            vector=vector,
        )
        self.findings[f.id] = f
        db.insert_finding(f.id, f.asset_name, f.title, f.metrics, f.score, f.severity, f.vector)
        return f

    def delete_finding(self, finding_id: str) -> None:
        if finding_id in self.findings:
            db.delete_finding(finding_id)
            del self.findings[finding_id]

    # --- Analytics ---
    def findings_for_asset_name(self, asset_name: str) -> List[Finding]:
        key = asset_name.strip().lower()
        return [f for f in self.findings.values() if f.asset_name.strip().lower() == key]

    def severity_counts(self) -> Dict[str, int]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
        for f in self.findings.values():
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
