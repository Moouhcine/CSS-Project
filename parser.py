import csv
import json
from typing import List, Dict, Any

REQUIRED = ["asset", "title", "AV", "AC", "PR", "UI", "S", "C", "I", "A"]

def _clean(s: Any) -> str:
    return ("" if s is None else str(s)).strip()

def parse_csv_text(csv_text: str) -> List[Dict[str, str]]:
    """
    CSV must include header keys: asset,title,AV,AC,PR,UI,S,C,I,A
    Delimiter can be a comma or a semicolon.
    """
    lines = csv_text.splitlines()
    if not lines:
        return []

    # Try to detect delimiter between comma and semicolon
    delimiter = ","
    sample = "\n".join(lines[:5])
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=[",", ";"])  # type: ignore[arg-type]
        delimiter = getattr(dialect, "delimiter", ",") or ","
    except Exception:
        header = lines[0]
        if ";" in header and (header.count(";") >= header.count(",")):
            delimiter = ";"

    reader = csv.DictReader(lines, delimiter=delimiter)
    findings: List[Dict[str, str]] = []
    for row in reader:
        item = {k: _clean(row.get(k)) for k in REQUIRED}
        if not item["asset"]:
            item["asset"] = "Unassigned"
        if not item["title"]:
            item["title"] = "Untitled Finding"
        # Uppercase metric codes
        for k in ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]:
            item[k] = item[k].upper()
        findings.append(item)
    return findings

def parse_json_text(json_text: str) -> List[Dict[str, str]]:
    """
    JSON must be a list of objects with keys: asset,title,AV,AC,PR,UI,S,C,I,A
    """
    data = json.loads(json_text)
    if not isinstance(data, list):
        raise ValueError("JSON must be a list of objects.")

    findings: List[Dict[str, str]] = []
    for obj in data:
        if not isinstance(obj, dict):
            continue
        item = {k: _clean(obj.get(k)) for k in REQUIRED}
        if not item["asset"]:
            item["asset"] = "Unassigned"
        if not item["title"]:
            item["title"] = "Untitled Finding"
        for k in ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]:
            item[k] = item[k].upper()
        findings.append(item)
    return findings
