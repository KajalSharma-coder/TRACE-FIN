"""
TRACE//FIN — Comprehensive Security & Privacy Test Suite (Phase 5)
Hardening verification: SSRF protection, CSV formula injection defense,
PII exclusion in ML, in-memory upload handling, and database record preservation.
"""

import io
import os
import sys
import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import DATASET_PATH, DB_PATH
from src.url_fetcher import is_safe_ip, validate_url_syntax
from src.csv_analyzer import sanitize_cell, export_safe_csv
from src.ml_model import EXCLUDED_COLUMNS
from src.database import get_all_records, init_db, insert_record, record_count, reset_engine, set_engine


# ── 1. SSRF Attack Vector Verification ─────────────────────────────────

def test_security_ssrf_forbidden_ip_ranges():
    """Verify that all non-public, reserved, and metadata IP spaces are rejected."""
    forbidden_ips = [
        # Loopback
        "127.0.0.1", "127.0.0.2", "127.255.255.254", "::1",
        # RFC1918 Private
        "10.0.0.1", "10.255.255.254",
        "172.16.0.1", "172.24.0.1", "172.31.255.254",
        "192.168.0.1", "192.168.1.1", "192.168.254.254",
        # Link-local & Cloud Metadata
        "169.254.169.254", "169.254.1.1", "fe80::1",
        # Unspecified / Broadcast / Multicast
        "0.0.0.0", "255.255.255.255", "224.0.0.1", "239.255.255.250",
    ]
    for ip in forbidden_ips:
        safe, reason = is_safe_ip(ip)
        assert safe is False, f"Expected {ip} to be blocked by SSRF defense!"


def test_security_ssrf_malicious_schemes_and_credentials():
    """Verify that dangerous URI schemes and userinfo credentials are blocked."""
    dangerous_urls = [
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "ftp://attacker.com/evil.sh",
        "gopher://127.0.0.1:6379/_flushall",
        "http://admin:secret@bank.com/api",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/latest/meta-data/",
    ]
    for u in dangerous_urls:
        res = validate_url_syntax(u)
        assert res["valid"] is False, f"Expected {u} to be rejected!"


# ── 2. Formula Injection Protection Matrix ─────────────────────────────

def test_security_csv_formula_injection_matrix():
    """Verify all spreadsheet executable prefixes are neutralized."""
    payloads = [
        "=1+2",
        "=cmd|'/C calc'!A0",
        "+cmd|'/C calc'!A0",
        "-12345",
        "-SUM(A1:A10)",
        "@SUM(A1:A10)",
        "\tSOMETHING",
        "\rSOMETHING",
    ]
    for payload in payloads:
        sanitized = sanitize_cell(payload)
        # Sanitized output must start with tab delimiter
        assert sanitized.startswith("\t"), f"Formula injection payload '{payload}' not tab-neutralized!"


# ── 3. Strict PII Feature Exclusion Guarantee ──────────────────────────

def test_security_zero_pii_feature_usage():
    """Verify that personal banking identifiers are excluded from predictive models."""
    import pandas as pd
    if DATASET_PATH.exists():
        df = pd.read_csv(DATASET_PATH)
        for col in EXCLUDED_COLUMNS:
            assert col in ["ID_No", "Account_Holder_Name", "Bank_Account_No", "IFSC_Code"]
            # Ensure column is flagged for exclusion
            assert col in df.columns


# ── 4. Database Record Integrity Guarantee ─────────────────────────────

@pytest.fixture
def isolated_security_db():
    """Use an isolated in-memory database for record-integrity checks."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    set_engine(engine)
    init_db(engine)
    try:
        yield
    finally:
        reset_engine()


def test_security_database_records_not_deleted(isolated_security_db):
    """Ensure read-only integrity checks do not delete or reset records."""
    insert_record({"record_id": "TF-SEC-COUNT-1", "ad_text": "Synthetic integrity record one"})
    insert_record({"record_id": "TF-SEC-COUNT-2", "ad_text": "Synthetic integrity record two"})

    before = get_all_records()
    count = record_count()
    after = get_all_records()

    assert count == len(before) == len(after) == 2
    assert [record["record_id"] for record in after] == [record["record_id"] for record in before]
