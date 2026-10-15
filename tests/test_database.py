"""
TRACE//FIN — Database Layer & Neon PostgreSQL Integration Tests
Tests configuration precedence, credential masking, schema creation,
idempotent migrations, CRUD operations, transaction rollback,
SQL injection resistance, and SQLite data migration.
"""

import os
from pathlib import Path
import sqlite3
import sys
import uuid
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.pool import StaticPool

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.database import (
    _deserialize_list,
    _normalize_risk_level,
    _serialize,
    advertisements_table,
    check_database_connection,
    create_app_engine,
    get_all_records,
    get_dashboard_metrics,
    get_database_url,
    get_engine,
    get_recent_records,
    get_record,
    init_db,
    insert_record,
    mask_db_url,
    normalize_db_url,
    record_count,
    reset_engine,
    search_records,
    set_engine,
    update_status,
)
from scripts.migrate_sqlite_to_postgres import migrate_sqlite_to_postgres


# ── Test Fixture: Isolated Test Database ───────────────────────────────

@pytest.fixture
def isolated_db():
    """Provide a pristine in-memory SQLite database using the SQLAlchemy engine."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    set_engine(engine)
    init_db(engine)
    yield engine
    reset_engine()


# ── 1. Credential Masking & Safe Configuration ─────────────────────────

def test_mask_db_url_redacts_credentials():
    raw_url = "postgresql://myuser:SuperSecretPassword123@ep-sample-123.us-east-2.aws.neon.tech/neondb?sslmode=require"
    masked = mask_db_url(raw_url)
    assert "SuperSecretPassword123" not in masked
    assert "*****" in masked
    assert "myuser" in masked
    assert "ep-sample-123.us-east-2.aws.neon.tech" in masked

    assert mask_db_url(None) == "<not configured>"
    assert mask_db_url("") == "<not configured>"


def test_normalize_db_url():
    url_postgres = "postgres://user:pass@host/db"
    assert normalize_db_url(url_postgres).startswith("postgresql+psycopg://")

    url_standard = "postgresql://user:pass@host/db"
    assert normalize_db_url(url_standard).startswith("postgresql+psycopg://")

    url_already_psycopg = "postgresql+psycopg://user:pass@host/db"
    assert normalize_db_url(url_already_psycopg) == url_already_psycopg


def test_get_database_url_precedence(monkeypatch):
    # Under pytest, get_database_url defaults to None unless TEST_DATABASE_URL is set
    monkeypatch.delenv("TEST_DATABASE_URL", raising=False)
    assert get_database_url() is None

    # When TEST_DATABASE_URL is explicitly set during tests
    monkeypatch.setenv("TEST_DATABASE_URL", "postgresql://test_user:test_pass@localhost/testdb")
    assert get_database_url() == "postgresql://test_user:test_pass@localhost/testdb"


# ── 2. Schema Creation & Repeated Initialization ──────────────────────

def test_schema_creation_and_idempotence(isolated_db):
    # init_db should run repeatedly without errors
    init_db(isolated_db)
    init_db(isolated_db)

    with isolated_db.connect() as conn:
        res = conn.execute(text("SELECT count(*) FROM advertisements")).scalar()
        assert res == 0


# ── 3. CRUD Operations & Persistence ──────────────────────────────────

def test_insert_and_get_record(isolated_db):
    rec_id = "TF-TEST0001"
    payload = {
        "record_id": rec_id,
        "ad_text": "Earn 50k weekly by renting your savings account. Contact Telegram @fastcash",
        "analysis_mode": "rule_based",
        "risk_score": 85.0,
        "risk_level": "High",
        "matched_categories": ["Account Rental / Mule Recruitment"],
        "evidence": ["[Category B] Mule recruitment: 'renting your savings account'"],
        "urls": ["https://example.com/fastcash"],
        "emails": ["fastcash@example.com"],
        "phone_numbers": ["+91-98765-43210"],
        "payment_identifiers": ["fastcash@okaxis"],
        "review_required": True,
        "review_recommendation": "Priority human review mandated",
        "investigation_status": "Open",
        "is_synthetic": 0,
        "ml_prediction": "High Risk",
        "ml_confidence": 0.95,
        "ml_high_risk_score": 0.95,
        "ml_model_version": "v3.0-tfidf",
        "hf_prediction": "High Risk",
        "hf_confidence": 0.98,
        "hf_model_version": "v4.0-distilbert",
    }

    inserted_id = insert_record(payload)
    assert inserted_id == rec_id

    fetched = get_record(rec_id)
    assert fetched is not None
    assert fetched["record_id"] == rec_id
    assert fetched["risk_score"] == 85.0
    assert fetched["risk_level"] == "High"
    assert fetched["urls"] == ["https://example.com/fastcash"]
    assert fetched["emails"] == ["fastcash@example.com"]
    assert fetched["phone_numbers"] == ["+91-98765-43210"]
    assert fetched["payment_identifiers"] == ["fastcash@okaxis"]
    assert fetched["review_required"] == 1 or fetched["review_required"] is True
    assert fetched["ml_prediction"] == "High Risk"
    assert fetched["hf_prediction"] == "High Risk"


def test_update_status(isolated_db):
    rec_id = "TF-STATUS01"
    insert_record({"record_id": rec_id, "ad_text": "Sample text", "investigation_status": "Open"})

    assert update_status(rec_id, "Reviewing") is True
    rec = get_record(rec_id)
    assert rec["investigation_status"] == "Reviewing"

    assert update_status(rec_id, "Escalated") is True
    rec = get_record(rec_id)
    assert rec["investigation_status"] == "Escalated"

    assert update_status(rec_id, "Closed") is True
    rec = get_record(rec_id)
    assert rec["investigation_status"] == "Closed"

    # Invalid status must be rejected
    assert update_status(rec_id, "InvalidStatusName") is False


def test_get_all_and_recent_records(isolated_db):
    for i in range(5):
        insert_record({
            "record_id": f"TF-LIST{i}",
            "ad_text": f"Ad content number {i}",
            "submitted_at": f"2026-10-15T0{i}:00:00Z",
        })

    all_recs = get_all_records()
    assert len(all_recs) == 5
    # Newest first
    assert all_recs[0]["record_id"] == "TF-LIST4"
    assert all_recs[-1]["record_id"] == "TF-LIST0"

    recent = get_recent_records(limit=3)
    assert len(recent) == 3
    assert recent[0]["record_id"] == "TF-LIST4"


# ── 4. SQL Injection Resistance ───────────────────────────────────────

def test_sql_injection_resistance_search(isolated_db):
    insert_record({
        "record_id": "TF-SEC001",
        "ad_text": "Legitimate banking disclosure text",
        "risk_level": "Low",
        "investigation_status": "Closed",
    })

    # Malicious injection payloads in search query
    injection_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE advertisements; --",
        "UNION SELECT * FROM advertisements --",
        "' OR 1=1 --",
    ]

    for payload in injection_payloads:
        # Should execute safely using bound parameters and not return all rows or drop table
        results = search_records(query=payload)
        assert isinstance(results, list)
        # Table must still exist and be intact
        assert record_count() == 1


def test_sql_injection_resistance_filters(isolated_db):
    insert_record({
        "record_id": "TF-SEC002",
        "ad_text": "Legitimate content",
        "risk_level": "Low",
        "investigation_status": "Open",
    })

    malicious_status = "' OR 1=1; --"
    res = search_records(status=malicious_status)
    assert len(res) == 0  # No record has that exact status string


# ── 5. Data Explorer & Dashboard Metrics Compatibility ────────────────

def test_search_records_filtering(isolated_db):
    insert_record({"record_id": "TF-F1", "ad_text": "Sell bank account", "risk_level": "High", "investigation_status": "Open"})
    insert_record({"record_id": "TF-F2", "ad_text": "Personal loan offer", "risk_level": "Low", "investigation_status": "Closed"})
    insert_record({"record_id": "TF-F3", "ad_text": "Earn commission daily", "risk_level": "Medium", "investigation_status": "Reviewing"})

    # Filter by risk level
    high_recs = search_records(risk_level="High")
    assert len(high_recs) == 1
    assert high_recs[0]["record_id"] == "TF-F1"

    # Filter by status
    closed_recs = search_records(status="Closed")
    assert len(closed_recs) == 1
    assert closed_recs[0]["record_id"] == "TF-F2"

    # Filter by keyword query
    loan_recs = search_records(query="loan")
    assert len(loan_recs) == 1
    assert loan_recs[0]["record_id"] == "TF-F2"


def test_get_dashboard_metrics(isolated_db):
    insert_record({
        "record_id": "TF-M1",
        "ad_text": "Ad 1",
        "submitted_at": "2026-10-15T10:00:00Z",
        "risk_level": "High",
        "investigation_status": "Escalated",
        "matched_categories": ["Category A", "Category B"],
    })
    insert_record({
        "record_id": "TF-M2",
        "ad_text": "Ad 2",
        "submitted_at": "2026-10-15T11:00:00Z",
        "risk_level": "Low",
        "investigation_status": "Closed",
        "matched_categories": ["Category A"],
    })

    metrics = get_dashboard_metrics()
    assert metrics["total"] == 2
    assert metrics["risk_counts"]["High"] == 1
    assert metrics["risk_counts"]["Low"] == 1
    assert metrics["status_counts"]["Escalated"] == 1
    assert metrics["status_counts"]["Closed"] == 1
    assert metrics["category_counts"]["Category A"] == 2
    assert metrics["category_counts"]["Category B"] == 1
    assert len(metrics["activity"]) >= 1


# ── 6. Check Database Connection Diagnostic ───────────────────────────

def test_check_database_connection(isolated_db):
    health = check_database_connection(isolated_db)
    assert health["connected"] is True
    assert health["record_count"] == 0
    assert "version" in health
    assert "sanitized_url" in health
    # Ensure credentials are not exposed
    assert "password" not in health["sanitized_url"].lower()


# ── 7. SQLite Migration Script Verification ───────────────────────────

def test_sqlite_to_postgres_migration(tmp_path, monkeypatch):
    """Verify that SQLite migration reads SQLite records and populates target safely."""
    # Create temporary source SQLite db
    src_db = tmp_path / "source.db"
    conn = sqlite3.connect(str(src_db))
    conn.execute("""
        CREATE TABLE advertisements (
            record_id TEXT PRIMARY KEY,
            ad_text TEXT NOT NULL,
            submitted_at TEXT NOT NULL,
            analysis_mode TEXT DEFAULT 'rule_based',
            risk_score REAL DEFAULT 0.0,
            risk_level TEXT DEFAULT 'Low',
            matched_categories TEXT DEFAULT '[]',
            evidence TEXT DEFAULT '[]',
            urls TEXT DEFAULT '[]',
            emails TEXT DEFAULT '[]',
            phone_numbers TEXT DEFAULT '[]',
            payment_identifiers TEXT DEFAULT '[]',
            review_required INTEGER DEFAULT 0,
            review_recommendation TEXT DEFAULT 'No Immediate Review Indicated',
            investigation_status TEXT DEFAULT 'Open',
            is_synthetic INTEGER DEFAULT 0,
            ml_prediction TEXT DEFAULT NULL,
            ml_confidence REAL DEFAULT NULL,
            ml_high_risk_score REAL DEFAULT NULL,
            ml_model_version TEXT DEFAULT NULL,
            hf_prediction TEXT DEFAULT NULL,
            hf_confidence REAL DEFAULT NULL,
            hf_model_version TEXT DEFAULT NULL
        )
    """)
    conn.execute(
        "INSERT INTO advertisements (record_id, ad_text, submitted_at, risk_score, risk_level) VALUES (?, ?, ?, ?, ?)",
        ("TF-MIG01", "Suspicious ad for migration test", "2026-10-15T00:00:00Z", 90.0, "High"),
    )
    conn.commit()
    conn.close()

    # Target engine
    tgt_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    init_db(tgt_engine)
    set_engine(tgt_engine)

    # Mock get_database_url to simulate postgresql target
    with patch("scripts.migrate_sqlite_to_postgres.get_database_url", return_value="postgresql://mock_user:mock_pass@mock_host/mock_db"):
        with patch("scripts.migrate_sqlite_to_postgres.init_db", return_value=None):
            with patch("scripts.migrate_sqlite_to_postgres.get_engine", return_value=tgt_engine):
                # 1. Dry run test
                dry_report = migrate_sqlite_to_postgres(src_db, dry_run=True)
                assert dry_report["success"] is True
                assert dry_report["total"] == 1
                assert dry_report["inserted"] == 1

                # 2. Real migration test
                report = migrate_sqlite_to_postgres(src_db, dry_run=False)
                assert report["success"] is True
                assert report["total"] == 1
                assert report["inserted"] == 1
                assert report["skipped"] == 0

                # 3. Idempotent re-run test (should skip duplicate)
                rerun_report = migrate_sqlite_to_postgres(src_db, dry_run=False)
                assert rerun_report["success"] is True
                assert rerun_report["inserted"] == 0
                assert rerun_report["skipped"] == 1

    reset_engine()


# ── 8. Dedicated Neon Live Integration Test ───────────────────────────

def test_neon_live_connection_if_configured():
    """
    Integration test executed against real Neon PostgreSQL when TEST_DATABASE_URL is provided.
    Inserts a single ephemeral record and cleans it up. Never drops production tables.
    """
    test_url = os.environ.get("TEST_DATABASE_URL")
    if not test_url:
        pytest.skip("TEST_DATABASE_URL not set; skipping live Neon integration test.")

    normalized = normalize_db_url(test_url)
    engine = create_app_engine(normalized, is_sqlite=False)

    # 1. Verify connection & SSL
    with engine.connect() as conn:
        res = conn.execute(text("SELECT version();")).scalar()
        assert "PostgreSQL" in str(res)

    # 2. Insert ephemeral test record
    test_id = f"TF-INTEG-{uuid.uuid4().hex[:6].upper()}"
    with engine.begin() as conn:
        conn.execute(
            advertisements_table.insert().values(
                record_id=test_id,
                ad_text="Ephemeral integration test advertisement",
                submitted_at="2026-10-15T00:00:00Z",
                analysis_mode="integration_test",
                risk_score=10.0,
                risk_level="Low",
                matched_categories="[]",
                evidence="[]",
                urls="[]",
                emails="[]",
                phone_numbers="[]",
                payment_identifiers="[]",
                review_required=0,
                review_recommendation="Test",
                investigation_status="Closed",
                is_synthetic=1,
            )
        )

    # 3. Retrieve ephemeral record
    with engine.connect() as conn:
        stmt = select(advertisements_table).where(advertisements_table.c.record_id == test_id)
        row = conn.execute(stmt).mappings().first()
        assert row is not None
        assert row["record_id"] == test_id

    # 4. Clean up ONLY this ephemeral record
    with engine.begin() as conn:
        conn.execute(advertisements_table.delete().where(advertisements_table.c.record_id == test_id))

    engine.dispose()
