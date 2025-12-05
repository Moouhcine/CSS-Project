from dataclasses import dataclass, field
from typing import Dict, List, Optional
import uuid

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

class Store:
    def __init__(self) -> None:
        self.assets: Dict[str, Asset] = {}
        self.findings: Dict[str, Finding] = {}

    def _id(self) -> str:
        return uuid.uuid4().hex

    # --- Assets ---
    def add_asset(self, name: str, tags: List[str], services: List[str]) -> Asset:
        a = Asset(id=self._id(), name=name.strip(), tags=tags, services=services)
        self.assets[a.id] = a
        return a

    def get_asset_by_name(self, name: str) -> Optional[Asset]:
        name = name.strip()
        for a in self.assets.values():
            if a.name == name:
                return a
        return None

    def delete_asset(self, asset_id: str) -> None:
        if asset_id in self.assets:
            del self.assets[asset_id]

    # --- Findings ---
    def add_finding(self, asset_name: str, title: str, metrics: Dict[str, str],
                    score: float, severity: str) -> Finding:
        f = Finding(
            id=self._id(),
            asset_name=asset_name.strip() or "Unassigned",
            title=title.strip() or "Untitled Finding",
            metrics=metrics,
            score=score,
            severity=severity,
        )
        self.findings[f.id] = f
        return f

    def delete_finding(self, finding_id: str) -> None:
        if finding_id in self.findings:
            del self.findings[finding_id]

    # --- Analytics ---
    def findings_for_asset_name(self, asset_name: str) -> List[Finding]:
        return [f for f in self.findings.values() if f.asset_name == asset_name]

    def severity_counts(self) -> Dict[str, int]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
        for f in self.findings.values():
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
