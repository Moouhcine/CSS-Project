import sqlite3
from typing import Dict, List, Optional, Tuple, Any

DB_PATH = "riskmapper.db"

def connect():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = connect()
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS assets (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        tags TEXT NOT NULL,
        services TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        asset_name TEXT NOT NULL,
        title TEXT NOT NULL,
        av TEXT NOT NULL,
        ac TEXT NOT NULL,
        pr TEXT NOT NULL,
        ui TEXT NOT NULL,
        s  TEXT NOT NULL,
        c  TEXT NOT NULL,
        i  TEXT NOT NULL,
        a  TEXT NOT NULL,
        score REAL NOT NULL,
        severity TEXT NOT NULL,
        vector TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
    )
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_name)")
    con.commit()
    con.close()

def _join_csv(items: List[str]) -> str:
    return ",".join([x.strip() for x in items if x.strip()])

def _split_csv(s: str) -> List[str]:
    s = (s or "").strip()
    if not s:
        return []
    return [x.strip() for x in s.split(",") if x.strip()]

# -------- Assets --------
def upsert_asset(asset_id: str, name: str, tags: List[str], services: List[str]) -> None:
    con = connect()
    cur = con.cursor()
    cur.execute("""
    INSERT INTO assets(id, name, tags, services)
    VALUES(?, ?, ?, ?)
    ON CONFLICT(name) DO UPDATE SET
        tags=excluded.tags,
        services=excluded.services
    """, (asset_id, name.strip(), _join_csv(tags), _join_csv(services)))
    con.commit()
    con.close()

def delete_asset(asset_id: str) -> None:
    con = connect()
    cur = con.cursor()
    cur.execute("DELETE FROM assets WHERE id=?", (asset_id,))
    con.commit()
    con.close()

def load_assets() -> List[Dict[str, Any]]:
    con = connect()
    cur = con.cursor()
    rows = cur.execute("SELECT id,name,tags,services FROM assets ORDER BY created_at DESC").fetchall()
    con.close()
    return [
        {
            "id": r["id"],
            "name": r["name"],
            "tags": _split_csv(r["tags"]),
            "services": _split_csv(r["services"]),
        }
        for r in rows
    ]

# -------- Findings --------
def insert_finding(
    finding_id: str,
    asset_name: str,
    title: str,
    metrics: Dict[str, str],
    score: float,
    severity: str,
    vector: str,
) -> None:
    con = connect()
    cur = con.cursor()
    cur.execute("""
    INSERT INTO findings(
      id, asset_name, title,
      av, ac, pr, ui, s, c, i, a,
      score, severity, vector
    )
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        finding_id,
        asset_name.strip(),
        title.strip(),
        metrics["AV"], metrics["AC"], metrics["PR"], metrics["UI"],
        metrics["S"], metrics["C"], metrics["I"], metrics["A"],
        float(score),
        severity,
        vector,
    ))
    con.commit()
    con.close()

def delete_finding(finding_id: str) -> None:
    con = connect()
    cur = con.cursor()
    cur.execute("DELETE FROM findings WHERE id=?", (finding_id,))
    con.commit()
    con.close()

def load_findings() -> List[Dict[str, Any]]:
    con = connect()
    cur = con.cursor()
    rows = cur.execute("""
    SELECT id, asset_name, title, av, ac, pr, ui, s, c, i, a, score, severity, vector
    FROM findings
    ORDER BY created_at DESC
    """).fetchall()
    con.close()

    out = []
    for r in rows:
        out.append({
            "id": r["id"],
            "asset_name": r["asset_name"],
            "title": r["title"],
            "metrics": {"AV": r["av"], "AC": r["ac"], "PR": r["pr"], "UI": r["ui"], "S": r["s"], "C": r["c"], "I": r["i"], "A": r["a"]},
            "score": float(r["score"]),
            "severity": r["severity"],
            "vector": r["vector"],
        })
    return out
