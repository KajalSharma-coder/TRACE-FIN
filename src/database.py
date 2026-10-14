"""
TRACE//FIN — SQLite Database Layer
All database operations are isolated here. Uses parameterized queries
and JSON serialization for list/dict fields.
"""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import DB_PATH, CASE_STATUSES


def _connect() -> sqlite3.Connection:
    """Return a connection with row-factory enabled."""
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _serialize(value: Any) -> str:
    """Serialize lists/dicts to JSON text for storage."""
    if value is None:
        return "[]"
    if isinstance(value, str):
        v = value.strip()
        if not v or v == "[]":
            return "[]"
        if v.startswith("[") and v.endswith("]"):
            try:
                parsed = json.loads(v)
                if isinstance(parsed, list):
                    return json.dumps(parsed)
            except Exception:
                pass
        return json.dumps([v])
    if isinstance(value, (list, tuple, set)):
        clean_list = [str(item).strip() for item in value if str(item).strip()]
        # Guard against saving list of single characters from accidental string iteration
        if all(len(c) == 1 for c in clean_list) and len(clean_list) > 3:
            return json.dumps(["".join(clean_list)])
        return json.dumps(clean_list)
    if isinstance(value, dict):
        return json.dumps(value)
    return json.dumps([str(value)])


def _deserialize_list(value: Any) -> list:
    """Deserialize a JSON text column back to a Python list."""
    if not value:
        return []
    if isinstance(value, (list, tuple, set)):
        items = [str(x).strip() for x in value if str(x).strip()]
        if all(len(c) == 1 for c in items) and len(items) > 3:
            return ["".join(items)]
        return items
    if not isinstance(value, str):
        return [str(value)]

    clean = value.strip()
    if not clean or clean == "[]":
        return []

    try:
        result = json.loads(clean)
        if isinstance(result, list):
            items = [str(item).strip() for item in result if str(item).strip()]
            if all(len(c) == 1 for c in items) and len(items) > 3:
                return ["".join(items)]
            return items
        s = str(result).strip()
        return [s] if s else []
    except (json.JSONDecodeError, TypeError):
        return [clean]


def _deserialize_evidence(value: str | None) -> list | dict:
    """Deserialize evidence JSON column whether stored as a list or a dict."""
    if not value:
        return []
    try:
        res = json.loads(value)
        if isinstance(res, (list, dict)):
            return res
        return [str(res)]
    except (json.JSONDecodeError, TypeError):
        return []


def _normalize_risk_level(raw: str | None) -> str:
    """Normalize risk levels to standardized title case (Critical, High, Medium, Low)."""
    if not raw:
        return "Low"
    s = str(raw).strip().upper()
    if s in ("MINIMAL", "LOW", "LOW RISK"):
        return "Low"
    if s in ("MEDIUM", "MEDIUM RISK", "MODERATE"):
        return "Medium"
    if s in ("HIGH", "HIGH RISK"):
        return "High"
    if s == "CRITICAL":
        return "Critical"
    return str(raw).capitalize()


def _row_to_dict(row: sqlite3.Row) -> dict:
    """Convert a Row to a plain dict with deserialized JSON fields."""
    d = dict(row)
    for key in ("matched_categories", "urls", "emails", "phone_numbers", "payment_identifiers"):
        d[key] = _deserialize_list(d.get(key))
    d["evidence"] = _deserialize_evidence(d.get("evidence"))
    d["risk_level"] = _normalize_risk_level(d.get("risk_level"))
    if "emails" not in d or d["emails"] is None:
        d["emails"] = []
    if "review_recommendation" not in d or not d["review_recommendation"]:
        d["review_recommendation"] = (
            "Investigator Review Recommended" if d.get("review_required")
            else "No Immediate Review Indicated"
        )
    d.setdefault("ml_prediction", None)
    d.setdefault("ml_confidence", None)
    d.setdefault("ml_high_risk_score", None)
    d.setdefault("ml_model_version", None)
    d.setdefault("hf_prediction", None)
    d.setdefault("hf_confidence", None)
    d.setdefault("hf_model_version", None)
    return d


# ── Schema ─────────────────────────────────────────────────────────────

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS advertisements (
    record_id              TEXT PRIMARY KEY,
    ad_text                TEXT NOT NULL,
    submitted_at           TEXT NOT NULL,
    analysis_mode          TEXT NOT NULL DEFAULT 'rule_based',
    risk_score             REAL DEFAULT 0.0,
    risk_level             TEXT DEFAULT 'Low',
    matched_categories     TEXT DEFAULT '[]',
    evidence               TEXT DEFAULT '[]',
    urls                   TEXT DEFAULT '[]',
    emails                 TEXT DEFAULT '[]',
    phone_numbers          TEXT DEFAULT '[]',
    payment_identifiers    TEXT DEFAULT '[]',
    review_required        INTEGER DEFAULT 0,
    review_recommendation  TEXT DEFAULT 'No Immediate Review Indicated',
    investigation_status   TEXT DEFAULT 'Open',
    is_synthetic           INTEGER DEFAULT 0,
    ml_prediction          TEXT DEFAULT NULL,
    ml_confidence          REAL DEFAULT NULL,
    ml_high_risk_score     REAL DEFAULT NULL,
    ml_model_version       TEXT DEFAULT NULL,
    hf_prediction          TEXT DEFAULT NULL,
    hf_confidence          REAL DEFAULT NULL,
    hf_model_version       TEXT DEFAULT NULL
);
"""

_CREATE_INDEX_RISK = """
CREATE INDEX IF NOT EXISTS idx_risk_level ON advertisements (risk_level);
"""

_CREATE_INDEX_STATUS = """
CREATE INDEX IF NOT EXISTS idx_investigation_status ON advertisements (investigation_status);
"""


def init_db() -> None:
    """Create schema if not existing (idempotent) and migrate columns/labels."""
    with _connect() as conn:
        conn.execute(_CREATE_TABLE)
        conn.execute(_CREATE_INDEX_RISK)
        conn.execute(_CREATE_INDEX_STATUS)

        # Check existing columns for safe schema evolution
        cursor = conn.execute("PRAGMA table_info(advertisements)")
        existing_cols = [r["name"] for r in cursor.fetchall()]

        if "review_recommendation" not in existing_cols:
            conn.execute(
                "ALTER TABLE advertisements ADD COLUMN review_recommendation TEXT DEFAULT 'No Immediate Review Indicated'"
            )
        if "emails" not in existing_cols:
            conn.execute(
                "ALTER TABLE advertisements ADD COLUMN emails TEXT DEFAULT '[]'"
            )

        # Phase 3 ML fields migration
        for ml_col, col_type in [
            ("ml_prediction", "TEXT DEFAULT NULL"),
            ("ml_confidence", "REAL DEFAULT NULL"),
            ("ml_high_risk_score", "REAL DEFAULT NULL"),
            ("ml_model_version", "TEXT DEFAULT NULL"),
        ]:
            if ml_col not in existing_cols:
                conn.execute(f"ALTER TABLE advertisements ADD COLUMN {ml_col} {col_type}")

        # Phase 4 HF fields migration
        for hf_col, col_type in [
            ("hf_prediction", "TEXT DEFAULT NULL"),
            ("hf_confidence", "REAL DEFAULT NULL"),
            ("hf_model_version", "TEXT DEFAULT NULL"),
        ]:
            if hf_col not in existing_cols:
                conn.execute(f"ALTER TABLE advertisements ADD COLUMN {hf_col} {col_type}")

        # Migrate legacy risk level labels to standardized title case
        conn.execute("UPDATE advertisements SET risk_level = 'Low' WHERE risk_level IN ('MINIMAL', 'Minimal', 'LOW', 'low')")
        conn.execute("UPDATE advertisements SET risk_level = 'Medium' WHERE risk_level IN ('MEDIUM', 'medium')")
        conn.execute("UPDATE advertisements SET risk_level = 'High' WHERE risk_level IN ('HIGH', 'high')")
        conn.execute("UPDATE advertisements SET risk_level = 'Critical' WHERE risk_level IN ('CRITICAL', 'critical')")

        conn.commit()


# ── Record ID ──────────────────────────────────────────────────────────

def generate_record_id() -> str:
    """Generate a short, human-friendly record ID."""
    short = uuid.uuid4().hex[:8].upper()
    return f"TF-{short}"


# ── CRUD ───────────────────────────────────────────────────────────────

def insert_record(record: dict) -> str:
    """Insert a new advertisement record. Returns the record_id."""
    record_id = record.get("record_id") or generate_record_id()
    now = record.get("submitted_at") or datetime.now(timezone.utc).isoformat()
    std_level = _normalize_risk_level(record.get("risk_level", "Low"))

    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO advertisements (
                record_id, ad_text, submitted_at, analysis_mode,
                risk_score, risk_level, matched_categories, evidence,
                urls, emails, phone_numbers, payment_identifiers,
                review_required, review_recommendation,
                investigation_status, is_synthetic,
                ml_prediction, ml_confidence, ml_high_risk_score, ml_model_version,
                hf_prediction, hf_confidence, hf_model_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record_id,
                record.get("ad_text", ""),
                now,
                record.get("analysis_mode", "rule_based"),
                float(record.get("risk_score", 0.0)),
                std_level,
                _serialize(record.get("matched_categories")),
                _serialize(record.get("evidence")),
                _serialize(record.get("urls")),
                _serialize(record.get("emails")),
                _serialize(record.get("phone_numbers")),
                _serialize(record.get("payment_identifiers")),
                1 if record.get("review_required") else 0,
                record.get("review_recommendation", "No Immediate Review Indicated"),
                record.get("investigation_status", "Open"),
                1 if record.get("is_synthetic") else 0,
                record.get("ml_prediction"),
                float(record["ml_confidence"]) if record.get("ml_confidence") is not None else None,
                float(record["ml_high_risk_score"]) if record.get("ml_high_risk_score") is not None else None,
                record.get("ml_model_version"),
                record.get("hf_prediction"),
                float(record["hf_confidence"]) if record.get("hf_confidence") is not None else None,
                record.get("hf_model_version"),
            ),
        )
        conn.commit()
    return record_id


def get_record(record_id: str) -> dict | None:
    """Retrieve a single record by ID."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM advertisements WHERE record_id = ?",
            (record_id,),
        ).fetchone()
    return _row_to_dict(row) if row else None


def get_all_records() -> list[dict]:
    """Retrieve all records ordered by submission time (newest first)."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM advertisements ORDER BY submitted_at DESC"
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_recent_records(limit: int = 10) -> list[dict]:
    """Retrieve the most recent records."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM advertisements ORDER BY submitted_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def update_status(record_id: str, new_status: str) -> bool:
    """Update investigation status. Returns True on success."""
    if new_status not in CASE_STATUSES:
        return False
    with _connect() as conn:
        cur = conn.execute(
            "UPDATE advertisements SET investigation_status = ? WHERE record_id = ?",
            (new_status, record_id),
        )
        conn.commit()
    return cur.rowcount > 0


def search_records(
    query: str = "",
    risk_level: str | None = None,
    status: str | None = None,
) -> list[dict]:
    """Search and filter records."""
    clauses: list[str] = []
    params: list[str] = []

    if query.strip():
        clauses.append("(record_id LIKE ? OR ad_text LIKE ?)")
        like = f"%{query.strip()}%"
        params.extend([like, like])

    if risk_level and risk_level != "All":
        clauses.append("LOWER(risk_level) = LOWER(?)")
        params.append(risk_level)

    if status and status != "All":
        clauses.append("investigation_status = ?")
        params.append(status)

    where = " AND ".join(clauses) if clauses else "1=1"
    sql = f"SELECT * FROM advertisements WHERE {where} ORDER BY submitted_at DESC"

    with _connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_dict(r) for r in rows]


# ── Dashboard Metrics ──────────────────────────────────────────────────

def get_dashboard_metrics() -> dict:
    """Aggregate metrics for dashboard, derived from stored records."""
    with _connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM advertisements").fetchone()[0]

        # Standardized risk counts dictionary
        risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for row in conn.execute(
            "SELECT risk_level, COUNT(*) as cnt FROM advertisements GROUP BY risk_level"
        ).fetchall():
            std_lvl = _normalize_risk_level(row["risk_level"])
            risk_counts[std_lvl] = risk_counts.get(std_lvl, 0) + row["cnt"]

        status_counts = {}
        for row in conn.execute(
            "SELECT investigation_status, COUNT(*) as cnt FROM advertisements GROUP BY investigation_status"
        ).fetchall():
            status_counts[row["investigation_status"]] = row["cnt"]

        # Activity over time (group by date)
        activity = []
        for row in conn.execute(
            """SELECT DATE(submitted_at) as day, COUNT(*) as cnt
               FROM advertisements GROUP BY day ORDER BY day"""
        ).fetchall():
            activity.append({"date": row["day"], "count": row["cnt"]})

        # Top matched categories across all records
        cat_rows = conn.execute(
            "SELECT matched_categories FROM advertisements"
        ).fetchall()

    # Aggregate categories
    cat_counts: dict[str, int] = {}
    for row in cat_rows:
        for cat in _deserialize_list(row["matched_categories"]):
            cat_counts[cat] = cat_counts.get(cat, 0) + 1

    return {
        "total": total,
        "risk_counts": risk_counts,
        "status_counts": status_counts,
        "activity": activity,
        "category_counts": cat_counts,
    }


def record_count() -> int:
    """Quick count of all records."""
    with _connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM advertisements").fetchone()[0]
