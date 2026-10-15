"""
TRACE//FIN — Enterprise Database Layer (PostgreSQL / Neon & Multi-Dialect)
Provides a secure, robust database interface powered by SQLAlchemy 2.0 and Psycopg 3.
Supports Neon-hosted PostgreSQL as the primary persistent database with connection pooling,
SSL, transaction safety, SQL injection protection, and idempotent schema migrations.
Seamlessly supports isolated testing environments and local fallback.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sys
from typing import Any
import uuid

from sqlalchemy import (
    Column,
    Float,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    and_,
    create_engine,
    func,
    insert,
    inspect,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.pool import StaticPool

from config import DB_PATH, CASE_STATUSES

logger = logging.getLogger("tracefin.database")

# ── Global Engine State ────────────────────────────────────────────────
_engine = None
_current_engine_target = None


# ── URL Resolution & Credential Security ───────────────────────────────

def mask_db_url(url: str | None) -> str:
    """Safely redact credentials from database URL for logging, UI, and diagnostics."""
    if not url:
        return "<not configured>"
    try:
        from urllib.parse import urlsplit, urlunsplit
        parsed = urlsplit(url)
        if parsed.password:
            netloc = f"{parsed.username or ''}:*****@{parsed.hostname or ''}"
            if parsed.port:
                netloc += f":{parsed.port}"
            return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))
        return url
    except Exception:
        return "<configured>"


def is_testing_environment() -> bool:
    """Detect whether code is executing under pytest test runner."""
    return ("pytest" in sys.modules) or bool(os.environ.get("PYTEST_CURRENT_TEST"))


def get_database_url() -> str | None:
    """
    Resolve DATABASE_URL with safe precedence:
    1. For automated unit tests without explicit TEST_DATABASE_URL: None (triggers isolated SQLite)
    2. Primary environment variable: os.environ['DATABASE_URL']
    3. Streamlit secrets: st.secrets['DATABASE_URL']
    4. Local development file: .env
    """
    if is_testing_environment():
        test_url = os.environ.get("TEST_DATABASE_URL")
        if test_url and test_url.strip():
            return test_url.strip()
        return None

    # 1. Primary environment variable
    env_url = os.environ.get("DATABASE_URL")
    if env_url and env_url.strip():
        return env_url.strip()

    # 2. Streamlit secrets (if available in Streamlit runtime)
    try:
        import streamlit as st
        if hasattr(st, "secrets") and "DATABASE_URL" in st.secrets:
            val = st.secrets["DATABASE_URL"]
            if val and str(val).strip():
                return str(val).strip()
    except Exception:
        pass

    # 3. Local .env file
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.exists():
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("DATABASE_URL=") and not line.startswith("#"):
                        val = line.split("=", 1)[1].strip().strip('"').strip("'")
                        if val:
                            return val
        except Exception:
            pass

    return None


def normalize_db_url(raw_url: str) -> str:
    """Ensure PostgreSQL URLs utilize the psycopg 3 driver for SQLAlchemy."""
    url = raw_url.strip()
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://"):]
    if url.startswith("postgresql://") and not url.startswith("postgresql+psycopg://"):
        return "postgresql+psycopg://" + url[len("postgresql://"):]
    return url


# ── Engine Lifecycle & Connection Pooling ─────────────────────────────

def create_app_engine(url: str, is_sqlite: bool = False):
    """
    Create a SQLAlchemy Engine with connection pool parameters tuned for Neon or SQLite.
    For Neon PostgreSQL: enables pool_pre_ping to survive serverless connection drops.
    """
    if is_sqlite:
        connect_args = {"check_same_thread": False}
        if ":memory:" in url:
            return create_engine(url, connect_args=connect_args, poolclass=StaticPool)
        return create_engine(url, connect_args=connect_args)

    # Neon PostgreSQL configuration
    return create_engine(
        url,
        pool_size=5,
        max_overflow=10,
        pool_timeout=30.0,
        pool_recycle=1800,
        pool_pre_ping=True,
    )


_engine = None
_custom_engine = False
_current_engine_target = None


def get_engine():
    """
    Retrieve or initialize the active SQLAlchemy Engine singleton.
    Dynamically responds to target URL or DB_PATH changes.
    """
    global _engine, _custom_engine, _current_engine_target

    if _engine is not None and _custom_engine:
        return _engine

    target_url = get_database_url()
    if target_url:
        normalized = normalize_db_url(target_url)
        target_key = ("postgres", normalized)
    else:
        DB_PATH.parent.mkdir(exist_ok=True)
        normalized = f"sqlite:///{DB_PATH}"
        target_key = ("sqlite", normalized)

    if _engine is not None and _current_engine_target == target_key:
        return _engine

    if _engine is not None:
        try:
            _engine.dispose()
        except Exception:
            pass

    if target_key[0] == "postgres":
        _engine = create_app_engine(target_key[1], is_sqlite=False)
        logger.info("Connected to PostgreSQL: %s", mask_db_url(target_url))
    else:
        _engine = create_app_engine(target_key[1], is_sqlite=True)
        if not is_testing_environment():
            logger.info("Using local SQLite database: %s", DB_PATH)

    _current_engine_target = target_key
    _custom_engine = False
    return _engine


def set_engine(engine) -> None:
    """Manually assign an engine instance (primarily for tests)."""
    global _engine, _custom_engine, _current_engine_target
    _engine = engine
    _custom_engine = True
    _current_engine_target = ("custom", str(engine.url))


def reset_engine() -> None:
    """Dispose and reset the current engine singleton."""
    global _engine, _custom_engine, _current_engine_target
    if _engine is not None:
        try:
            _engine.dispose()
        except Exception:
            pass
    _engine = None
    _custom_engine = False
    _current_engine_target = None


# ── Serialization & Normalization Helpers ──────────────────────────────

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


def _row_to_dict(row: Any) -> dict:
    """Convert a database row (RowMapping or dict) to a plain dict with deserialized JSON fields."""
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


# ── Schema Definition ──────────────────────────────────────────────────

metadata = MetaData()

advertisements_table = Table(
    "advertisements",
    metadata,
    Column("record_id", String(64), primary_key=True),
    Column("ad_text", Text, nullable=False),
    Column("submitted_at", String(64), nullable=False, index=True),
    Column("analysis_mode", String(64), nullable=False, server_default="rule_based"),
    Column("risk_score", Float, server_default="0.0"),
    Column("risk_level", String(32), server_default="Low", index=True),
    Column("matched_categories", Text, server_default="[]"),
    Column("evidence", Text, server_default="[]"),
    Column("urls", Text, server_default="[]"),
    Column("emails", Text, server_default="[]"),
    Column("phone_numbers", Text, server_default="[]"),
    Column("payment_identifiers", Text, server_default="[]"),
    Column("review_required", Integer, server_default="0"),
    Column("review_recommendation", Text, server_default="No Immediate Review Indicated"),
    Column("investigation_status", String(32), server_default="Open", index=True),
    Column("is_synthetic", Integer, server_default="0"),
    Column("ml_prediction", String(64), nullable=True),
    Column("ml_confidence", Float, nullable=True),
    Column("ml_high_risk_score", Float, nullable=True),
    Column("ml_model_version", String(64), nullable=True),
    Column("hf_prediction", String(64), nullable=True),
    Column("hf_confidence", Float, nullable=True),
    Column("hf_model_version", String(64), nullable=True),
)


def init_db(engine=None) -> None:
    """Create schema if not existing (idempotent) and migrate columns/labels."""
    eng = engine or get_engine()
    metadata.create_all(eng)

    # Safe schema migration for missing columns
    inspector = inspect(eng)
    existing_cols = {c["name"] for c in inspector.get_columns("advertisements")}

    with eng.begin() as conn:
        for col_name, col_type in [
            ("review_recommendation", "TEXT DEFAULT 'No Immediate Review Indicated'"),
            ("emails", "TEXT DEFAULT '[]'"),
            ("ml_prediction", "TEXT DEFAULT NULL"),
            ("ml_confidence", "FLOAT DEFAULT NULL"),
            ("ml_high_risk_score", "FLOAT DEFAULT NULL"),
            ("ml_model_version", "TEXT DEFAULT NULL"),
            ("hf_prediction", "TEXT DEFAULT NULL"),
            ("hf_confidence", "FLOAT DEFAULT NULL"),
            ("hf_model_version", "TEXT DEFAULT NULL"),
        ]:
            if col_name not in existing_cols:
                try:
                    conn.execute(text(f"ALTER TABLE advertisements ADD COLUMN {col_name} {col_type}"))
                except Exception as exc:
                    logger.debug("Column %s could not be added (may already exist): %s", col_name, exc)

        # Normalize legacy risk level labels
        try:
            conn.execute(text("UPDATE advertisements SET risk_level = 'Low' WHERE risk_level IN ('MINIMAL', 'Minimal', 'LOW', 'low')"))
            conn.execute(text("UPDATE advertisements SET risk_level = 'Medium' WHERE risk_level IN ('MEDIUM', 'medium')"))
            conn.execute(text("UPDATE advertisements SET risk_level = 'High' WHERE risk_level IN ('HIGH', 'high')"))
            conn.execute(text("UPDATE advertisements SET risk_level = 'Critical' WHERE risk_level IN ('CRITICAL', 'critical')"))
        except Exception as exc:
            logger.debug("Risk level normalization encountered exception: %s", exc)


# ── Record ID ──────────────────────────────────────────────────────────

def generate_record_id() -> str:
    """Generate a short, human-friendly record ID."""
    short = uuid.uuid4().hex[:8].upper()
    return f"TF-{short}"


# ── CRUD Operations ────────────────────────────────────────────────────

def insert_record(record: dict) -> str:
    """Insert a new advertisement record. Returns the record_id."""
    record_id = record.get("record_id") or generate_record_id()
    now = record.get("submitted_at") or datetime.now(timezone.utc).isoformat()
    std_level = _normalize_risk_level(record.get("risk_level", "Low"))

    values = {
        "record_id": record_id,
        "ad_text": record.get("ad_text", ""),
        "submitted_at": now,
        "analysis_mode": record.get("analysis_mode", "rule_based"),
        "risk_score": float(record["risk_score"]) if record.get("risk_score") is not None else None,
        "risk_level": std_level,
        "matched_categories": _serialize(record.get("matched_categories")),
        "evidence": _serialize(record.get("evidence")),
        "urls": _serialize(record.get("urls")),
        "emails": _serialize(record.get("emails")),
        "phone_numbers": _serialize(record.get("phone_numbers")),
        "payment_identifiers": _serialize(record.get("payment_identifiers")),
        "review_required": 1 if record.get("review_required") else 0,
        "review_recommendation": record.get("review_recommendation", "No Immediate Review Indicated"),
        "investigation_status": record.get("investigation_status", "Open"),
        "is_synthetic": 1 if record.get("is_synthetic") else 0,
        "ml_prediction": record.get("ml_prediction"),
        "ml_confidence": float(record["ml_confidence"]) if record.get("ml_confidence") is not None else None,
        "ml_high_risk_score": float(record["ml_high_risk_score"]) if record.get("ml_high_risk_score") is not None else None,
        "ml_model_version": record.get("ml_model_version"),
        "hf_prediction": record.get("hf_prediction"),
        "hf_confidence": float(record["hf_confidence"]) if record.get("hf_confidence") is not None else None,
        "hf_model_version": record.get("hf_model_version"),
    }

    eng = get_engine()
    with eng.begin() as conn:
        conn.execute(insert(advertisements_table).values(**values))
    return record_id


def get_record(record_id: str) -> dict | None:
    """Retrieve a single record by ID."""
    eng = get_engine()
    stmt = select(advertisements_table).where(advertisements_table.c.record_id == record_id)
    with eng.connect() as conn:
        row = conn.execute(stmt).mappings().first()
    return _row_to_dict(row) if row else None


def get_all_records() -> list[dict]:
    """Retrieve all records ordered by submission time (newest first)."""
    eng = get_engine()
    stmt = select(advertisements_table).order_by(advertisements_table.c.submitted_at.desc())
    with eng.connect() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_dict(r) for r in rows]


def get_recent_records(limit: int = 10) -> list[dict]:
    """Retrieve the most recent records."""
    eng = get_engine()
    stmt = select(advertisements_table).order_by(advertisements_table.c.submitted_at.desc()).limit(limit)
    with eng.connect() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_dict(r) for r in rows]


def update_status(record_id: str, new_status: str) -> bool:
    """Update investigation status. Returns True on success."""
    if new_status not in CASE_STATUSES:
        return False
    eng = get_engine()
    stmt = (
        update(advertisements_table)
        .where(advertisements_table.c.record_id == record_id)
        .values(investigation_status=new_status)
    )
    with eng.begin() as conn:
        res = conn.execute(stmt)
    return res.rowcount > 0


def search_records(
    query: str = "",
    risk_level: str | None = None,
    status: str | None = None,
) -> list[dict]:
    """Search and filter records."""
    eng = get_engine()
    conditions = []

    if query and query.strip():
        pattern = f"%{query.strip()}%"
        conditions.append(
            or_(
                advertisements_table.c.record_id.ilike(pattern),
                advertisements_table.c.ad_text.ilike(pattern),
            )
        )

    if risk_level and risk_level != "All":
        conditions.append(func.lower(advertisements_table.c.risk_level) == risk_level.strip().lower())

    if status and status != "All":
        conditions.append(advertisements_table.c.investigation_status == status.strip())

    stmt = select(advertisements_table)
    if conditions:
        stmt = stmt.where(and_(*conditions))
    stmt = stmt.order_by(advertisements_table.c.submitted_at.desc())

    with eng.connect() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [_row_to_dict(r) for r in rows]


def record_count() -> int:
    """Quick count of all records."""
    eng = get_engine()
    stmt = select(func.count()).select_from(advertisements_table)
    with eng.connect() as conn:
        return conn.execute(stmt).scalar() or 0


# ── Dashboard Metrics ──────────────────────────────────────────────────

def get_dashboard_metrics() -> dict:
    """Aggregate metrics for dashboard, derived from stored records."""
    eng = get_engine()
    with eng.connect() as conn:
        total = conn.execute(select(func.count()).select_from(advertisements_table)).scalar() or 0

        # Standardized risk counts dictionary
        risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        risk_stmt = (
            select(advertisements_table.c.risk_level, func.count().label("cnt"))
            .group_by(advertisements_table.c.risk_level)
        )
        for row in conn.execute(risk_stmt).mappings().all():
            std_lvl = _normalize_risk_level(row["risk_level"])
            risk_counts[std_lvl] = risk_counts.get(std_lvl, 0) + int(row["cnt"])

        status_counts = {}
        status_stmt = (
            select(advertisements_table.c.investigation_status, func.count().label("cnt"))
            .group_by(advertisements_table.c.investigation_status)
        )
        for row in conn.execute(status_stmt).mappings().all():
            status_counts[row["investigation_status"]] = int(row["cnt"])

        # Activity over time (group by day YYYY-MM-DD)
        day_expr = func.substr(advertisements_table.c.submitted_at, 1, 10).label("day")
        activity_stmt = select(day_expr, func.count().label("cnt")).group_by(day_expr).order_by(day_expr)
        activity = []
        for row in conn.execute(activity_stmt).mappings().all():
            activity.append({"date": row["day"], "count": int(row["cnt"])})

        # Top matched categories across all records
        cat_stmt = select(advertisements_table.c.matched_categories)
        cat_rows = conn.execute(cat_stmt).scalars().all()

    # Aggregate categories in Python
    cat_counts: dict[str, int] = {}
    for raw_cat in cat_rows:
        for cat in _deserialize_list(raw_cat):
            cat_counts[cat] = cat_counts.get(cat, 0) + 1

    return {
        "total": total,
        "risk_counts": risk_counts,
        "status_counts": status_counts,
        "activity": activity,
        "category_counts": cat_counts,
    }


# ── Diagnostics & Connection Health ────────────────────────────────────

def check_database_connection(engine: Engine | None = None) -> dict[str, Any]:
    """
    Check the current database connection health, returning status and metadata.
    Never exposes passwords or secret credentials in return dictionaries.
    """
    if engine is not None and hasattr(engine, "url"):
        raw_url = str(engine.url)
    else:
        raw_url = get_database_url()

    is_postgres = bool(raw_url and ("postgres" in raw_url.lower()))

    result = {
        "connected": False,
        "is_postgres": is_postgres,
        "database_type": "PostgreSQL (Neon)" if is_postgres else "SQLite (Local/Fallback)",
        "sanitized_url": mask_db_url(raw_url) if raw_url else f"sqlite:///{DB_PATH}",
        "error": None,
        "version": None,
        "record_count": 0,
    }

    try:
        eng = engine or get_engine()
        with eng.connect() as conn:
            ver = conn.execute(text("SELECT version();" if is_postgres else "SELECT sqlite_version();")).scalar()
            cnt = conn.execute(select(func.count()).select_from(advertisements_table)).scalar() or 0
            result["connected"] = True
            result["version"] = str(ver).splitlines()[0] if ver else "Unknown"
            result["record_count"] = int(cnt)
    except Exception as exc:
        result["error"] = str(exc).splitlines()[0]
        logger.error("Database connection check failed: %s", result["error"])

    return result
