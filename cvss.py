import math
from dataclasses import dataclass
from typing import Dict

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC = {"L": 0.77, "H": 0.44}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.00}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}

METRIC_FIELDS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]

ALLOWED = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "R"},
    "S": {"U", "C"},
    "C": {"H", "L", "N"},
    "I": {"H", "L", "N"},
    "A": {"H", "L", "N"},
}

@dataclass(frozen=True)
class CvssResult:
    score: float
    severity: str
    impact: float
    exploitability: float

def round_up_1_decimal(x: float) -> float:
    return math.ceil(x * 10.0 - 1e-9) / 10.0

def severity(score: float) -> str:
    if score == 0.0:
        return "None"
    if 0.1 <= score <= 3.9:
        return "Low"
    if 4.0 <= score <= 6.9:
        return "Medium"
    if 7.0 <= score <= 8.9:
        return "High"
    return "Critical"

def validate_metrics(metrics: Dict[str, str]) -> None:
    for k in METRIC_FIELDS:
        if k not in metrics:
            raise ValueError(f"Missing metric: {k}")
        v = (metrics[k] or "").strip().upper()
        if v not in ALLOWED[k]:
            raise ValueError(f"Invalid {k}: '{v}'. Allowed: {sorted(ALLOWED[k])}")

def calculate_base_score(metrics: Dict[str, str]) -> CvssResult:
    m = {k: (metrics[k] or "").strip().upper() for k in METRIC_FIELDS}
    validate_metrics(m)

    av = AV[m["AV"]]
    ac = AC[m["AC"]]
    ui = UI[m["UI"]]
    scope = m["S"]

    pr = (PR_C if scope == "C" else PR_U)[m["PR"]]

    c = CIA[m["C"]]
    i = CIA[m["I"]]
    a = CIA[m["A"]]

    exploitability = 8.22 * av * ac * pr * ui
    isc_base = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

    if scope == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

    if impact <= 0:
        score = 0.0
    else:
        if scope == "U":
            score = min(impact + exploitability, 10.0)
        else:
            score = min(1.08 * (impact + exploitability), 10.0)

    score = round_up_1_decimal(score)
    impact = round_up_1_decimal(max(impact, 0.0))
    exploitability = round_up_1_decimal(exploitability)

    return CvssResult(
        score=score,
        severity=severity(score),
        impact=impact,
        exploitability=exploitability,
    )
    
    
def vector_string(metrics: Dict[str, str]) -> str:

    m = {k: (metrics[k] or "").strip().upper() for k in METRIC_FIELDS}
    validate_metrics(m)
    parts = ["CVSS:3.1"]
    for k in ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]:
        parts.append(f"{k}:{m[k]}")
    return "/".join(parts)

