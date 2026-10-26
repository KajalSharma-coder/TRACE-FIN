"""
TRACE//FIN — Unified Multi-Format Input Audit & Parity Test Suite
Validates the complete triage pipeline across all supported intake channels:
1. Direct text intake
2. Website URL (live webpage retrieval & syntax-only fallback)
3. Screenshot / image upload and OCR (Tesseract)
4. PDF document upload and text extraction
5. Word document (DOCX) upload and text extraction
6. CSV batch advertisement analysis

Verifies:
- Extraction fidelity and error handling
- Uniform multi-engine analysis (Rules -> TF-IDF ML -> DistilBERT -> compute_unified_verdict)
- Equivalent scoring on standardized suspicious vs. legitimate benchmarks
- Defense against empty, corrupt, or syntax-only inputs (INSUFFICIENT EVIDENCE)
- Complete database persistence schema across all input modes
"""

import io
import os
import sys
import tempfile
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch
import pandas as pd
import pytest

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.analysis_service import (
    run_unified_analysis,
    persist_analysis_record,
    STATUS_SUCCESS,
    STATUS_EMPTY_INPUT,
    STATUS_INSUFFICIENT_CONTENT,
    STATUS_EXTRACTION_FAILED,
    STATUS_SYNTAX_ONLY,
)
from src.url_fetcher import analyze_url
from src.ocr_engine import validate_image, extract_text_ocr
from src.document_extractor import extract_pdf_text, extract_docx_text
from src.csv_analyzer import run_batch_analysis, sanitize_cell, export_safe_csv
import src.database as db_module


# ── Benchmark Test Content ──────────────────────────────────────────────

BENCHMARK_SUSPICIOUS_TEXT = (
    "Urgent financial opportunity: Rent your personal bank account for instant cashout service! "
    "Receive transfers into your account and keep 10% daily commission. Guaranteed loan approval, "
    "no CIBIL or credit check required. Transfer Rs 2,500 advance loan release fee before disbursement. "
    "Enter your OTP and netbanking login password to claim fast payout. "
    "Contact Telegram @fastcashout, phone 9876543210, UPI fastcash@okaxis."
)

BENCHMARK_LEGITIMATE_TEXT = (
    "Vendor payment details: Rohan Kumar, Bank: HDFC, Acc: 66562328946, IFSC: HDFC0437589. "
    "Routine invoice settlement for quarterly IT equipment maintenance services. Thank you."
)


# ── Fixtures & In-Memory Isolation ─────────────────────────────────────

@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    """Provide a pristine SQLite database for testing without modifying data/tracefin.db."""
    test_db_path = tmp_path / "test_tracefin.db"
    monkeypatch.setattr(db_module, "DB_PATH", test_db_path)
    db_module.init_db()
    try:
        yield test_db_path
    finally:
        # The application database layer owns a process-wide SQLAlchemy engine.
        # Dispose it before Windows attempts to remove the temporary SQLite file.
        db_module.reset_engine()
        if test_db_path.exists():
            test_db_path.unlink()


class MockUploadedFile:
    """Mock file upload object simulating Streamlit UploadedFile."""
    def __init__(self, name: str, data: bytes):
        self.name = name
        self._io = io.BytesIO(data)
        self.size = len(data)

    def read(self, *args, **kwargs):
        return self._io.read(*args, **kwargs)

    def seek(self, *args, **kwargs):
        return self._io.seek(*args, **kwargs)


def _create_mock_docx(text: str) -> bytes:
    """Generate in-memory docx bytes with given text."""
    import docx
    doc = docx.Document()
    doc.add_paragraph(text)
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# ── Method 1: Direct Text Input Tests ───────────────────────────────────

def test_direct_text_suspicious_benchmark(isolated_db):
    """Test Direct Text input with the suspicious benchmark advertisement."""
    res = run_unified_analysis(
        text=BENCHMARK_SUSPICIOUS_TEXT,
        source_type="Direct Text",
        source_metadata={"input_method": "direct_text"},
    )

    assert res["extraction_status"] == STATUS_SUCCESS
    assert res["has_sufficient_evidence"] is True
    assert res["final_verdict"] == "HIGH RISK"
    assert res["final_score"] >= 75
    assert res["analyzed_text"] == BENCHMARK_SUSPICIOUS_TEXT
    assert res["evidence"]
    assert any("bank account" in item.lower() for item in res["evidence"])
    assert res["rule_score"] >= 50
    assert len(res["matched_rules"]) >= 2
    assert "9876543210" in res["phone_numbers"]

    # Verify isolated persistence
    rec_id = persist_analysis_record(res)
    saved = db_module.get_record(rec_id)
    assert saved is not None
    assert saved["risk_level"] in ("High", "Critical")
    assert saved["risk_score"] == res["final_score"]
    assert saved["analysis_mode"] == "direct_text_unified"
    assert "Telegram" in saved["ad_text"]


def test_legitimate_and_suspicious_loan_ads_end_to_end(isolated_db):
    legitimate = run_unified_analysis(
        "ABC Finance offers personal loans at a disclosed annual interest rate. "
        "Eligibility depends on income and credit checks. Review the repayment schedule "
        "and terms on our official website before applying."
    )
    suspicious = run_unified_analysis(
        "Guaranteed loan approval with no CIBIL check. Pay a processing fee before "
        "disbursement and send your OTP and UPI PIN to release the funds."
    )

    assert legitimate["final_score"] <= 24
    assert legitimate["final_verdict"] == "LOW RISK"
    assert suspicious["matched_categories"]
    assert "Suspicious Financial Solicitation" in suspicious["matched_categories"]
    assert suspicious["final_verdict"] == "HIGH RISK"
    assert suspicious["review_required"] is True


def test_direct_text_legitimate_benchmark():
    """Test Direct Text input with the legitimate banking advisory benchmark."""
    res = run_unified_analysis(
        text=BENCHMARK_LEGITIMATE_TEXT,
        source_type="Direct Text",
    )

    assert res["extraction_status"] == STATUS_SUCCESS
    assert res["has_sufficient_evidence"] is True
    assert res["final_verdict"] == "LOW RISK"
    assert res["final_score"] <= 30
    assert res["rule_score"] == 0
    assert res["review_required"] is False
    assert "Routine" in res["recommendation"] or "Low Priority" in res["recommendation"]


def test_direct_text_empty_input():
    """Test Direct Text input with empty or whitespace-only content."""
    res = run_unified_analysis(
        text="   ",
        source_type="Direct Text",
    )

    assert res["extraction_status"] == STATUS_EMPTY_INPUT
    assert res["has_sufficient_evidence"] is False
    assert res["final_verdict"] == "INSUFFICIENT EVIDENCE"
    assert res["final_score"] is None
    assert res["investigation_status"] == "Reviewing"


# ── Method 2: Website URL Input Tests ───────────────────────────────────

@patch("src.url_fetcher.safe_fetch_url")
def test_website_url_suspicious_live_page(mock_fetch, isolated_db):
    """Test Website URL pipeline with live webpage content retrieval."""
    mock_fetch.return_value = {
        "success": True,
        "error": None,
        "extracted_text": BENCHMARK_SUSPICIOUS_TEXT,
        "title": "Loan Offer",
        "status_code": 200,
        "final_url": "https://fastcash-promo.xyz/deal",
        "content_type": "text/html",
        "size_kb": 1.2,
        "indicators": [],
        "warnings": [],
    }

    url_res = analyze_url("https://fastcash-promo.xyz/deal", fetch_content=True)
    assert url_res["valid"] is True
    assert url_res["extracted_text"] is not None
    assert "Rent your personal bank account" in url_res["extracted_text"]

    # Process through unified analysis
    res = run_unified_analysis(
        text=url_res["extracted_text"],
        source_type="Website URL",
        source_metadata={"final_url": url_res["final_url"], "hostname": url_res["hostname"]},
    )

    assert res["has_sufficient_evidence"] is True
    assert res["final_verdict"] == "HIGH RISK"
    assert res["final_score"] >= 75

    rec_id = persist_analysis_record(res)
    saved = db_module.get_record(rec_id)
    assert saved["analysis_mode"] == "website_url_unified"
    assert saved["risk_level"] in ("High", "Critical")


@patch("src.url_fetcher.safe_fetch_url")
def test_website_url_legitimate_live_page(mock_fetch):
    """Test Website URL pipeline with legitimate advisory content."""
    mock_fetch.return_value = {
        "success": True,
        "error": None,
        "extracted_text": BENCHMARK_LEGITIMATE_TEXT,
        "title": "Axis Bank Security",
        "status_code": 200,
        "final_url": "https://axisbank.com/security-advisory",
        "content_type": "text/html",
        "size_kb": 2.5,
        "indicators": [],
        "warnings": [],
    }

    url_res = analyze_url("https://axisbank.com/security-advisory", fetch_content=True)
    assert url_res["valid"] is True

    res = run_unified_analysis(
        text=url_res["extracted_text"],
        source_type="Website URL",
        source_metadata={"final_url": url_res["final_url"]},
    )

    assert res["final_verdict"] == "LOW RISK"
    assert res["final_score"] <= 30


def test_website_url_ssrf_blocked():
    """Test that private IPs / internal networks are safely blocked before fetch."""
    blocked_urls = [
        "http://127.0.0.1:8000/ad",
        "http://192.168.1.1/admin",
        "http://169.254.169.254/latest/meta-data",
        "http://localhost/loan",
    ]
    for url in blocked_urls:
        url_res = analyze_url(url, fetch_content=True)
        assert url_res["success"] is False
        assert any(term in url_res["error"].lower() for term in ("blocked", "disallowed", "ssrf", "loopback", "private"))

        # Check analysis service handling of blocked fetch
        res = run_unified_analysis(
            text=None,
            source_type="Website URL",
            extraction_status=STATUS_EXTRACTION_FAILED,
            extraction_error=url_res["error"],
        )
        assert res["has_sufficient_evidence"] is False
        assert res["final_verdict"] == "INSUFFICIENT EVIDENCE"
        assert res["final_score"] is None


def test_website_url_syntax_only_mode():
    """Test Website URL syntax-only inspection without page retrieval."""
    url_res = analyze_url("https://unverified-fastloan.biz/offer", fetch_content=False)
    assert url_res["valid"] is True
    assert not url_res.get("extracted_text")

    res = run_unified_analysis(
        text=f"URL domain analysis: {url_res['hostname']}",
        source_type="Website URL (Syntax Only)",
        extraction_status=STATUS_SYNTAX_ONLY,
    )

    assert res["has_sufficient_evidence"] is False
    assert res["final_verdict"] == "INSUFFICIENT EVIDENCE"
    assert res["final_score"] is None
    assert "domain syntax" in res["explanation"].lower()
    assert res["investigation_status"] == "Reviewing"


# ── Method 3: Image / Screenshot OCR Tests ──────────────────────────────

@patch("src.ocr_engine.extract_text_ocr")
def test_image_ocr_suspicious_benchmark(mock_ocr, isolated_db):
    """Test Image OCR pipeline with suspicious benchmark advertisement."""
    mock_ocr.return_value = {
        "text": BENCHMARK_SUSPICIOUS_TEXT,
        "confidence": 92.5,
        "error": None,
        "available": True,
    }

    ocr_out = mock_ocr(None)
    assert ocr_out["available"] is True

    res = run_unified_analysis(
        text=ocr_out["text"],
        source_type="Image OCR",
        source_metadata={"confidence": ocr_out["confidence"], "file_name": "poster.png"},
    )

    assert res["has_sufficient_evidence"] is True
    assert res["final_verdict"] == "HIGH RISK"
    assert res["final_score"] >= 75

    rec_id = persist_analysis_record(res)
    saved = db_module.get_record(rec_id)
    assert saved["analysis_mode"] == "image_ocr_unified"
    assert saved["risk_level"] in ("High", "Critical")


@patch("src.ocr_engine.extract_text_ocr")
def test_image_ocr_legitimate_benchmark(mock_ocr):
    """Test Image OCR pipeline with legitimate advisory content."""
    mock_ocr.return_value = {
        "text": BENCHMARK_LEGITIMATE_TEXT,
        "confidence": 88.0,
        "error": None,
        "available": True,
    }

    ocr_out = mock_ocr(None)
    res = run_unified_analysis(
        text=ocr_out["text"],
        source_type="Image OCR",
    )

    assert res["final_verdict"] == "LOW RISK"
    assert res["final_score"] <= 30


def test_image_ocr_failed_extraction():
    """Test Image OCR handling when OCR yields no text or errors."""
    res = run_unified_analysis(
        text="",
        source_type="Image OCR",
        extraction_status=STATUS_EXTRACTION_FAILED,
        extraction_error="No readable text detected in image.",
    )

    assert res["has_sufficient_evidence"] is False
    assert res["final_verdict"] == "INSUFFICIENT EVIDENCE"
    assert res["final_score"] is None


# ── Method 4: PDF Document Upload Tests ─────────────────────────────────

@patch("src.document_extractor.extract_pdf_text")
def test_pdf_upload_suspicious_benchmark(mock_pdf, isolated_db):
    """Test PDF upload and extraction with suspicious benchmark content."""
    mock_pdf.return_value = {
        "valid": True,
        "text": BENCHMARK_SUSPICIOUS_TEXT,
        "metadata": {"total_pages": 1, "size_kb": 45.2},
        "warnings": [],
        "error": None,
    }

    doc_out = mock_pdf(None)
    res = run_unified_analysis(
        text=doc_out["text"],
        source_type="PDF Document",
        source_metadata=doc_out["metadata"],
    )

    assert res["has_sufficient_evidence"] is True
    assert res["final_verdict"] == "HIGH RISK"
    assert res["final_score"] >= 75

    rec_id = persist_analysis_record(res)
    saved = db_module.get_record(rec_id)
    assert saved["analysis_mode"] == "pdf_document_unified"
    assert saved["risk_level"] in ("High", "Critical")


def test_pdf_suspicious_text_reaches_rules_with_models_unavailable(monkeypatch):
    """A successful PDF text handoff must preserve rule evidence without model fallback scoring."""
    suspicious_text = (
        "Guaranteed ₹10,000 monthly earnings. Renting a bank account for transfers. "
        "Send bank login credentials and OTP. Pay a ₹1,499 advance activation fee. "
        "Forward incoming transfers and avoid contacting the bank."
    )
    monkeypatch.setattr(
        "src.analysis_service.predict_ad_ml",
        lambda _text: {"available": False, "risk_label": None, "confidence": None},
    )
    monkeypatch.setattr(
        "src.analysis_service.predict_ad_hf",
        lambda _text: {"available": False, "risk_label": None, "confidence": None},
    )

    result = run_unified_analysis(suspicious_text, source_type="PDF Document")

    assert result["analyzed_text"] == suspicious_text
    assert result["final_score"] > 0
    assert result["rule_score"] > 0
    assert result["final_verdict"] in {"MEDIUM RISK", "HIGH RISK"}
    assert result["matched_categories"]
    assert result["evidence"]
    assert result["engine_status"]["distilbert"] == "unavailable"


@patch("src.document_extractor.extract_pdf_text")
def test_pdf_upload_legitimate_benchmark(mock_pdf):
    """Test PDF upload and extraction with legitimate advisory content."""
    mock_pdf.return_value = {
        "valid": True,
        "text": BENCHMARK_LEGITIMATE_TEXT,
        "metadata": {"total_pages": 2, "size_kb": 120.0},
        "warnings": [],
        "error": None,
    }

    doc_out = mock_pdf(None)
    res = run_unified_analysis(
        text=doc_out["text"],
        source_type="PDF Document",
    )

    assert res["final_verdict"] == "LOW RISK"
    assert res["final_score"] <= 30


def test_pdf_corrupt_file_handling():
    """Test PDF extraction on corrupt file bytes."""
    corrupt_mock = MockUploadedFile("corrupt.pdf", b"NOT_A_VALID_PDF_HEADER_123")
    extract_res = extract_pdf_text(corrupt_mock)
    assert extract_res["valid"] is False
    assert extract_res["error"] is not None

    res = run_unified_analysis(
        text=None,
        source_type="PDF Document",
        extraction_status=STATUS_EXTRACTION_FAILED,
        extraction_error=extract_res["error"],
    )

    assert res["has_sufficient_evidence"] is False
    assert res["final_verdict"] == "INSUFFICIENT EVIDENCE"
    assert res["final_score"] is None


# ── Method 5: Word Document (DOCX) Upload Tests ─────────────────────────

def test_docx_upload_suspicious_benchmark(isolated_db):
    """Test real in-memory DOCX generation, extraction, and threat analysis."""
    docx_bytes = _create_mock_docx(BENCHMARK_SUSPICIOUS_TEXT)
    mock_doc = MockUploadedFile("campaign_memo.docx", docx_bytes)

    extract_res = extract_docx_text(mock_doc)
    assert extract_res["valid"] is True
    assert extract_res["text"] is not None
    assert "Rent your personal bank account" in extract_res["text"]

    res = run_unified_analysis(
        text=extract_res["text"],
        source_type="Word Document",
        source_metadata=extract_res["metadata"],
    )

    assert res["has_sufficient_evidence"] is True
    assert res["final_verdict"] == "HIGH RISK"
    assert res["final_score"] >= 75

    rec_id = persist_analysis_record(res)
    saved = db_module.get_record(rec_id)
    assert saved["analysis_mode"] == "word_document_unified"
    assert saved["risk_level"] in ("High", "Critical")


def test_docx_upload_legitimate_benchmark():
    """Test real in-memory DOCX generation and analysis for legitimate content."""
    docx_bytes = _create_mock_docx(BENCHMARK_LEGITIMATE_TEXT)
    mock_doc = MockUploadedFile("security_brief.docx", docx_bytes)

    extract_res = extract_docx_text(mock_doc)
    assert extract_res["valid"] is True

    res = run_unified_analysis(
        text=extract_res["text"],
        source_type="Word Document",
    )

    assert res["final_verdict"] == "LOW RISK"
    assert res["final_score"] <= 30


def test_docx_corrupt_file_handling():
    """Test DOCX extraction on non-zip corrupt file bytes."""
    corrupt_mock = MockUploadedFile("corrupt.docx", b"NOT_A_ZIP_CONTAINER_DOCX")
    extract_res = extract_docx_text(corrupt_mock)
    assert extract_res["valid"] is False
    assert extract_res["error"] is not None

    res = run_unified_analysis(
        text=None,
        source_type="Word Document",
        extraction_status=STATUS_EXTRACTION_FAILED,
        extraction_error=extract_res["error"],
    )

    assert res["has_sufficient_evidence"] is False
    assert res["final_verdict"] == "INSUFFICIENT EVIDENCE"


# ── Method 6: CSV Batch Analysis Tests ─────────────────────────────────

def test_csv_batch_suspicious_and_legitimate_benchmarks():
    """Test CSV batch analysis triage on both benchmark advertisements."""
    df_input = pd.DataFrame({
        "Ad_ID": [101, 102],
        "Ad_Content": [BENCHMARK_SUSPICIOUS_TEXT, BENCHMARK_LEGITIMATE_TEXT],
    })

    results = run_batch_analysis(df_input, text_column="Ad_Content", include_hf=False)

    assert len(results) == 2
    # Row 0: Suspicious
    row_susp = results.iloc[0]
    assert row_susp["final_verdict"] == "HIGH RISK"
    assert row_susp["risk_score"] >= 70
    assert row_susp["risk_level"] in ("High", "Critical")
    assert row_susp["review_required"] in (True, "Yes")

    # Row 1: Legitimate
    row_legit = results.iloc[1]
    assert row_legit["final_verdict"] == "LOW RISK"
    assert row_legit["risk_score"] <= 30
    assert row_legit["risk_level"] == "Low"


def test_csv_formula_injection_defense():
    """Test formula injection defense for spreadsheet export."""
    dangerous_inputs = ["=SUM(A1:A10)", "+cmd|' /C calc'!A0", "-2+3*[4]", "@EXEC('malicious')"]
    for val in dangerous_inputs:
        sanitized = sanitize_cell(val)
        assert sanitized.startswith("\t"), f"Failed to sanitize formula injection prefix: {val}"


# ── Cross-Method Parity & Invariant Matrix ──────────────────────────────

def test_cross_method_suspicious_equivalence():
    """
    Parity Invariant:
    Passing identical suspicious benchmark content through any ingestion channel
    must yield the exact same final risk verdict, rule matches, and critical indicators.
    """
    sources = [
        "Direct Text",
        "Website URL",
        "Image OCR",
        "PDF Document",
        "Word Document",
    ]
    results = [
        run_unified_analysis(BENCHMARK_SUSPICIOUS_TEXT, source_type=src)
        for src in sources
    ]

    for idx, r in enumerate(results):
        assert r["final_verdict"] == "HIGH RISK", f"Source {sources[idx]} failed HIGH RISK verdict"
        assert r["final_score"] >= 75, f"Source {sources[idx]} final score {r['final_score']} below threshold"
        assert r["rule_score"] >= 50, f"Source {sources[idx]} rule score {r['rule_score']} below threshold"
        assert len(r["matched_rules"]) >= 2, f"Source {sources[idx]} missed rule indicators"
        assert "9876543210" in r["phone_numbers"]


def test_cross_method_legitimate_equivalence():
    """
    Parity Invariant:
    Passing identical legitimate benchmark content through any ingestion channel
    must consistently produce LOW RISK with zero false-positive rule flags.
    """
    sources = [
        "Direct Text",
        "Website URL",
        "Image OCR",
        "PDF Document",
        "Word Document",
    ]
    results = [
        run_unified_analysis(BENCHMARK_LEGITIMATE_TEXT, source_type=src)
        for src in sources
    ]

    for idx, r in enumerate(results):
        assert r["final_verdict"] == "LOW RISK", f"Source {sources[idx]} produced false positive"
        assert r["final_score"] <= 30, f"Source {sources[idx]} final score {r['final_score']} too high"
        assert r["rule_score"] == 0, f"Source {sources[idx]} matched unexpected rules"


def test_unavailable_models_are_reported_and_persist_unscored(monkeypatch, isolated_db):
    """The service and database preserve the distinction between missing models and safe."""
    monkeypatch.setattr(
        "src.analysis_service.predict_ad_ml",
        lambda _text: {"available": False, "risk_label": None, "error": "model artifact missing"},
    )
    monkeypatch.setattr(
        "src.analysis_service.predict_ad_hf",
        lambda _text: {"available": False, "risk_label": None, "error": "fine-tuned weights missing"},
    )

    result = run_unified_analysis("Routine update about quarterly marketing plans.")
    assert result["final_verdict"] == "INSUFFICIENT EVIDENCE"
    assert result["final_score"] is None
    assert result["has_sufficient_evidence"] is False
    assert "model artifact missing" in " ".join(result["evidence"])
    assert result["engine_status"] == {
        "rules": "available",
        "tfidf": "unavailable",
        "distilbert": "unavailable",
    }

    record_id = persist_analysis_record(result)
    saved = db_module.get_record(record_id)
    assert saved["risk_level"] == "Insufficient evidence"
    assert saved["risk_score"] is None


def test_local_triage_needs_no_external_ai_credentials(monkeypatch):
    """Rules and the local TF-IDF model still work without provider credentials."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("HF_TOKEN", raising=False)
    # DistilBERT is optional/local. Simulate its weights being unavailable;
    # this project does not call a hosted inference API as a fallback.
    monkeypatch.setattr(
        "src.analysis_service.predict_ad_hf",
        lambda _text: {
            "available": False,
            "risk_label": None,
            "error": "Local DistilBERT weights unavailable (offline).",
        },
    )

    suspicious = run_unified_analysis(BENCHMARK_SUSPICIOUS_TEXT)
    legitimate = run_unified_analysis(BENCHMARK_LEGITIMATE_TEXT)

    assert suspicious["final_verdict"] == "HIGH RISK"
    assert suspicious["rule_score"] >= 50
    assert suspicious["ml_prediction"] == "High Risk"
    assert suspicious["engine_status"]["distilbert"] == "unavailable"
    assert "offline" in " ".join(suspicious["evidence"]).lower()

    assert legitimate["final_verdict"] == "LOW RISK"
    assert legitimate["rule_score"] == 0
    assert legitimate["ml_prediction"] == "Safe"
    assert legitimate["engine_status"]["distilbert"] == "unavailable"
