import sqlite3
import io
from datetime import datetime, timedelta, timezone

import pytest
import pandas as pd
from fastapi.testclient import TestClient
from PIL import Image

import src.auth as auth_module
import backend.api.main as api_module
from backend.api.main import app


@pytest.fixture
def auth_client(tmp_path, monkeypatch):
    db_path = tmp_path / "accounts.sqlite3"
    monkeypatch.setattr(auth_module, "DB_PATH", db_path)
    monkeypatch.setenv("TRACEFIN_AUTH_COOKIE_SECURE", "false")
    auth_module.create_user(
        "Analyst",
        "analyst@example.org",
        "correct horse battery staple",
        "correct horse battery staple",
        db_path,
    )
    return TestClient(app)


def csrf_for(client: TestClient) -> str:
    response = client.get("/api/auth/csrf")
    assert response.status_code == 200
    token = response.json()["csrf_token"]
    assert token
    return token


def login_for(client: TestClient, csrf: str | None = None):
    token = csrf or csrf_for(client)
    return client.post(
        "/api/auth/login",
        headers={"X-CSRF-Token": token},
        json={"email": "analyst@example.org", "password": "correct horse battery staple"},
    )


def test_login_success_returns_safe_identity_and_secure_cookie_shape(auth_client):
    csrf = csrf_for(auth_client)
    response = login_for(auth_client, csrf)

    assert response.status_code == 200
    assert response.json() == {
        "user": {"id": 1, "name": "Analyst", "email": "analyst@example.org"}
    }
    assert "password_hash" not in response.text
    assert "session_token" not in response.text

    set_cookie = response.headers["set-cookie"].lower()
    assert "tracefin_session=" in set_cookie
    assert "httponly" in set_cookie
    assert "samesite=strict" in set_cookie
    assert "path=/" in set_cookie


def test_login_rejects_wrong_credentials_without_leaking_details(auth_client):
    csrf = csrf_for(auth_client)
    response = auth_client.post(
        "/api/auth/login",
        headers={"X-CSRF-Token": csrf},
        json={"email": "analyst@example.org", "password": "wrong password"},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password."}


@pytest.mark.parametrize(
    "headers",
    [{}, {"X-CSRF-Token": "wrong-token"}],
)
def test_login_requires_csrf_proof(auth_client, headers):
    csrf_for(auth_client)
    response = auth_client.post(
        "/api/auth/login",
        headers=headers,
        json={"email": "analyst@example.org", "password": "correct horse battery staple"},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "CSRF validation failed."}


def test_current_session_accepts_valid_cookie_and_rejects_missing_session(auth_client):
    assert auth_client.get("/api/auth/session").status_code == 401
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200

    response = auth_client.get("/api/auth/session")
    assert response.status_code == 200
    assert response.json()["user"]["email"] == "analyst@example.org"


def test_invalid_and_expired_sessions_are_rejected(auth_client):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200

    auth_client.cookies.clear()
    auth_client.cookies.set(
        auth_module.AUTH_COOKIE_NAME, "not-a-real-session", path="/"
    )
    invalid = auth_client.get("/api/auth/session")
    assert invalid.status_code == 401

    # Re-authenticate, then expire the stored session without changing schema or
    # production data; this is isolated to the fixture database.
    auth_client.cookies.clear()
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    db_path = auth_module.DB_PATH
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE local_auth_sessions SET expires_at = ?",
            ((datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),),
        )
    expired = auth_client.get("/api/auth/session")
    assert expired.status_code == 401


def test_logout_requires_csrf_and_revokes_session(auth_client):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200

    missing_csrf = auth_client.post("/api/auth/logout")
    assert missing_csrf.status_code == 403
    assert auth_client.get("/api/auth/session").status_code == 200

    logout = auth_client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    assert logout.status_code == 204
    assert auth_client.get("/api/auth/session").status_code == 401


def test_csrf_cookie_is_not_httponly_but_is_same_site(auth_client, monkeypatch):
    monkeypatch.setenv("TRACEFIN_AUTH_COOKIE_SECURE", "true")
    response = auth_client.get("/api/auth/csrf")
    set_cookie = response.headers["set-cookie"].lower()

    assert "tracefin_csrf=" in set_cookie
    assert "samesite=strict" in set_cookie
    assert "secure" in set_cookie
    assert "httponly" not in set_cookie


def test_dashboard_requires_an_authenticated_session(auth_client):
    response = auth_client.get("/api/dashboard")
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required."}


def test_dashboard_returns_existing_aggregates_after_authentication(auth_client, monkeypatch):
    records = [
        {
            "record_id": "saved-1",
            "ad_text": "A suspicious advertisement with sensitive detail",
            "risk_score": 82,
            "risk_level": "Critical",
            "investigation_status": "Open",
            "submitted_at": "2026-10-23T12:00:00",
            "matched_categories": ["credential_harvesting"],
            "is_synthetic": False,
            "evidence": ["must not be returned"],
        },
        {"record_id": "demo-1", "risk_level": "Low", "is_synthetic": True},
    ]
    monkeypatch.setattr("backend.api.main.get_all_records", lambda: records)

    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    response = auth_client.get("/api/dashboard")

    assert response.status_code == 200
    assert response.json() == {
        "total": 1,
        "risk_counts": {"Critical": 1, "High": 0, "Medium": 0, "Low": 0},
        "status_counts": {"Open": 1},
        "activity": [{"date": "2026-10-23", "count": 1}],
        "category_counts": {"credential_harvesting": 1},
        "recent": [
            {
                "record_id": "saved-1",
                "advertisement": "A suspicious advertisement with sensitive detail",
                "risk_score": 82,
                "risk_level": "Critical",
                "status": "Open",
                "submitted_at": "2026-10-23T12:00:00",
            }
        ],
        "demo_count": 1,
    }
    assert "evidence" not in response.text


def test_dashboard_storage_failure_is_safe(auth_client, monkeypatch):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    monkeypatch.setattr(
        "backend.api.main.get_all_records",
        lambda: (_ for _ in ()).throw(OSError("private database path")),
    )

    response = auth_client.get("/api/dashboard")
    assert response.status_code == 503
    assert response.json() == {"detail": "Dashboard data unavailable."}
    assert "private database path" not in response.text


def test_analysis_requires_authentication_and_csrf(auth_client):
    response = auth_client.post("/api/analyze", json={"text": "suspicious offer"})
    assert response.status_code == 401

    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    response = auth_client.post("/api/analyze", json={"text": "suspicious offer"})
    assert response.status_code == 403


def test_authenticated_analysis_returns_existing_service_contract(auth_client, monkeypatch):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    monkeypatch.setattr(
        api_module,
        "run_unified_analysis",
        lambda **kwargs: {
            "source_type": "Direct Text",
            "extraction_status": "success",
            "has_sufficient_evidence": True,
            "final_verdict": "HIGH RISK",
            "final_score": 80,
            "risk_score": 80,
            "risk_level": "HIGH RISK",
            "rule_score": 70,
            "rule_level": "High",
            "matched_categories": ["credential_harvesting"],
            "explanation": "Existing service explanation.",
            "recommendation": "Escalate for review.",
            "investigation_status": "Escalated",
            "review_required": True,
            "consensus_status": "Consensus Threat",
            "engine_status": {"rules": "available", "tfidf": "unavailable", "distilbert": "unavailable"},
            "ml_prediction": None,
            "ml_confidence": None,
            "hf_prediction": None,
            "hf_confidence": None,
        },
    )

    response = auth_client.post(
        "/api/analyze",
        headers={"X-CSRF-Token": csrf},
        json={"text": "suspicious offer"},
    )

    assert response.status_code == 200
    assert response.json()["final_verdict"] == "HIGH RISK"
    assert response.json()["engine_status"] == {
        "rules": "available",
        "tfidf": "unavailable",
        "distilbert": "unavailable",
    }
    assert response.json()["ml_prediction"] is None
    assert response.json()["hf_prediction"] is None


def test_analysis_invalid_input_and_service_failure_are_safe(auth_client, monkeypatch):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200

    invalid = auth_client.post(
        "/api/analyze",
        headers={"X-CSRF-Token": csrf},
        json={"text": ""},
    )
    assert invalid.status_code == 422
    assert invalid.json() == {"detail": "Invalid request."}

    monkeypatch.setattr(
        api_module,
        "run_unified_analysis",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("private model path and secret")),
    )
    failed = auth_client.post(
        "/api/analyze",
        headers={"X-CSRF-Token": csrf},
        json={"text": "suspicious offer"},
    )
    assert failed.status_code == 503
    assert failed.json() == {"detail": "Analysis service unavailable."}
    assert "private model path" not in failed.text


def test_url_analysis_requires_auth_and_csrf(auth_client):
    response = auth_client.post(
        "/api/analyze-url", json={"url": "https://example.org", "fetch_content": False}
    )
    assert response.status_code == 401

    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    response = auth_client.post(
        "/api/analyze-url",
        json={"url": "https://example.org", "fetch_content": False},
    )
    assert response.status_code == 403


def test_url_analysis_preserves_syntax_only_and_model_status(auth_client, monkeypatch):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    monkeypatch.setattr(
        api_module,
        "analyze_url",
        lambda url, fetch_content: {
            "valid": True,
            "success": True,
            "url": url,
            "final_url": url,
            "error": None,
            "failure_category": None,
            "analysis_mode": "syntax_only",
            "disclosure": "URL structure and domain-only analysis (no remote connection made).",
            "hostname": "example.org",
            "title": "",
            "extracted_text": "",
            "indicators": ["[URL Structure] Example indicator."],
            "warnings": [],
            "status_code": None,
            "bytes_downloaded": 0,
            "redirect_history": [],
            "url_model": {
                "available": False,
                "prediction": None,
                "phishing_probability": None,
                "model": "url-model",
                "error": "private model path",
            },
        },
    )

    response = auth_client.post(
        "/api/analyze-url",
        headers={"X-CSRF-Token": csrf},
        json={"url": "https://example.org", "fetch_content": False},
    )

    assert response.status_code == 200
    assert response.json()["analysis_mode"] == "syntax_only"
    assert response.json()["url_model"]["available"] is False
    assert response.json()["url_model"]["error"] == "URL model unavailable."
    assert "private model path" not in response.text


def test_url_analysis_returns_unified_ad_score_separately_from_url_model(auth_client, monkeypatch):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    suspicious_text = (
        "Guaranteed earnings of 10000 daily. Rent out your bank account, receive and "
        "forward transfers, and send your bank password and OTP. Pay an advance fee."
    )
    monkeypatch.setattr(
        api_module,
        "analyze_url",
        lambda url, fetch_content: {
            "valid": True,
            "success": True,
            "url": url,
            "final_url": url,
            "error": None,
            "failure_category": None,
            "analysis_mode": "live_fetch",
            "disclosure": "Safely retrieved remote HTML content without code execution.",
            "hostname": "example.org",
            "title": "",
            "extracted_text": suspicious_text,
            "indicators": [],
            "warnings": [],
            "status_code": 200,
            "bytes_downloaded": len(suspicious_text),
            "redirect_history": [],
            "url_model": {
                "available": False,
                "prediction": None,
                "phishing_probability": None,
                "model": "url-model",
                "error": "model unavailable",
            },
        },
    )

    response = auth_client.post(
        "/api/analyze-url",
        headers={"X-CSRF-Token": csrf},
        json={"url": "https://example.org/offer", "fetch_content": True},
    )

    assert response.status_code == 200
    payload = response.json()
    ad_analysis = payload["advertisement_analysis"]
    assert isinstance(ad_analysis["final_score"], int)
    assert ad_analysis["final_score"] > 0
    assert ad_analysis["final_verdict"] != "UNKNOWN"
    assert payload["url_model"]["available"] is False
    assert payload["url_model"]["phishing_probability"] is None
    assert payload["url_model"]["error"] == "URL model unavailable."


def test_url_analysis_preserves_explicit_unscored_ad_analysis(auth_client, monkeypatch):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    monkeypatch.setattr(
        api_module,
        "analyze_url",
        lambda url, fetch_content: {
            "valid": True,
            "success": True,
            "url": url,
            "final_url": url,
            "error": None,
            "failure_category": None,
            "analysis_mode": "live_fetch",
            "disclosure": "Retrieved content contained no usable text.",
            "hostname": "example.org",
            "title": "",
            "extracted_text": "Short",
            "indicators": [],
            "warnings": [],
            "status_code": 200,
            "bytes_downloaded": 5,
            "redirect_history": [],
            "url_model": {"available": False, "error": "missing"},
        },
    )
    monkeypatch.setattr(
        api_module,
        "run_unified_analysis",
        lambda **kwargs: {
            "source_type": "URL Content",
            "extraction_status": "insufficient",
            "has_sufficient_evidence": False,
            "final_verdict": "INSUFFICIENT EVIDENCE",
            "final_score": None,
            "risk_score": None,
            "risk_level": "Unscored",
            "rule_score": None,
            "rule_level": "Unknown",
            "matched_categories": [],
            "evidence": [],
            "explanation": "No usable content was available for scoring.",
            "recommendation": "Obtain additional evidence.",
            "investigation_status": "Open",
            "review_required": True,
            "consensus_status": "Insufficient Evidence",
            "engine_status": {"rules": "unavailable", "tfidf": "unavailable", "distilbert": "unavailable"},
            "ml_prediction": None,
            "ml_confidence": None,
            "hf_prediction": None,
            "hf_confidence": None,
        },
    )

    response = auth_client.post(
        "/api/analyze-url",
        headers={"X-CSRF-Token": csrf},
        json={"url": "https://example.org/short", "fetch_content": True},
    )

    assert response.status_code == 200
    payload = response.json()["advertisement_analysis"]
    assert payload["final_score"] is None
    assert payload["final_verdict"] == "INSUFFICIENT EVIDENCE"
    assert payload["explanation"]


def test_url_analysis_invalid_scheme_and_ssrf_failure_are_safe(auth_client, monkeypatch):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200

    invalid = auth_client.post(
        "/api/analyze-url",
        headers={"X-CSRF-Token": csrf},
        json={"url": "file:///etc/passwd", "fetch_content": True},
    )
    assert invalid.status_code == 200
    assert invalid.json()["valid"] is False
    assert invalid.json()["analysis_mode"] == "syntax_only"

    monkeypatch.setattr(
        api_module,
        "analyze_url",
        lambda url, fetch_content: {
            "valid": True,
            "success": False,
            "url": url,
            "final_url": url,
            "error": "SSRF protection blocked hop 0",
            "failure_category": "ssrf_blocked",
            "analysis_mode": "fetch_failed",
            "disclosure": "Live fetch failed; relying on domain syntax.",
            "hostname": "public.example",
            "title": "",
            "extracted_text": "",
            "indicators": [],
            "warnings": [],
            "status_code": None,
            "bytes_downloaded": 0,
            "redirect_history": [],
            "url_model": {"available": False},
        },
    )
    blocked = auth_client.post(
        "/api/analyze-url",
        headers={"X-CSRF-Token": csrf},
        json={"url": "https://public.example", "fetch_content": True},
    )
    assert blocked.status_code == 200
    assert blocked.json()["failure_category"] == "ssrf_blocked"
    assert "SSRF protection blocked" in blocked.json()["error"]


def _image_bytes(format_name="PNG", size=(120, 80)):
    buffer = io.BytesIO()
    Image.new("RGB", size, color=(20, 80, 120)).save(buffer, format=format_name)
    return buffer.getvalue()


def test_image_ocr_requires_auth_and_csrf(auth_client):
    response = auth_client.post(
        "/api/image-ocr",
        files={"image": ("ad.png", _image_bytes(), "image/png")},
    )
    assert response.status_code == 401

    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    response = auth_client.post(
        "/api/image-ocr",
        files={"image": ("ad.png", _image_bytes(), "image/png")},
    )
    assert response.status_code == 403


def test_image_ocr_validates_supported_upload_and_returns_ocr_without_persisting(auth_client, monkeypatch):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    captured = {}

    def fake_ocr(image):
        captured["image"] = image
        return {
            "text": "Bank account offer",
            "confidence": 92.5,
            "error": None,
            "available": True,
            "engine": "Tesseract",
        }

    monkeypatch.setattr(api_module, "extract_text_ocr", fake_ocr)
    response = auth_client.post(
        "/api/image-ocr",
        headers={"X-CSRF-Token": csrf},
        files={"image": ("ad.png", _image_bytes(), "image/png")},
    )

    assert response.status_code == 200
    assert response.json()["valid"] is True
    assert response.json()["dimensions"] == [120, 80]
    assert response.json()["ocr"] == {
        "text": "Bank account offer",
        "confidence": 92.5,
        "error": None,
        "available": True,
        "engine": "Tesseract",
    }
    assert captured["image"] is not None


def test_image_ocr_handles_malformed_oversized_and_wrong_mime_uploads(auth_client):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    headers = {"X-CSRF-Token": csrf}

    malformed = auth_client.post(
        "/api/image-ocr",
        headers=headers,
        files={"image": ("ad.png", b"not-an-image", "image/png")},
    )
    assert malformed.status_code == 200
    assert malformed.json()["valid"] is False
    assert malformed.json()["error"] == "Corrupt or unreadable image file."

    oversized = auth_client.post(
        "/api/image-ocr",
        headers=headers,
        files={"image": ("ad.png", b"x" * (10 * 1024 * 1024 + 1), "image/png")},
    )
    assert oversized.status_code == 200
    assert oversized.json()["valid"] is False
    assert "10 MB" in oversized.json()["error"]

    wrong_mime = auth_client.post(
        "/api/image-ocr",
        headers=headers,
        files={"image": ("ad.png", _image_bytes(), "application/octet-stream")},
    )
    assert wrong_mime.status_code == 422
    assert wrong_mime.json() == {"detail": "Unsupported image content type."}


@pytest.mark.parametrize(
    "ocr_result",
    [
        {"text": "", "confidence": None, "error": "No readable text", "available": True, "engine": "Tesseract"},
        {"text": "", "confidence": None, "error": "engine missing", "available": False, "engine": None},
    ],
)
def test_image_ocr_preserves_empty_or_unavailable_ocr_state(auth_client, monkeypatch, ocr_result):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    monkeypatch.setattr(api_module, "extract_text_ocr", lambda image: ocr_result)
    response = auth_client.post(
        "/api/image-ocr",
        headers={"X-CSRF-Token": csrf},
        files={"image": ("ad.jpg", _image_bytes("JPEG"), "image/jpeg")},
    )
    assert response.status_code == 200
    assert response.json()["ocr"]["text"] == ""
    assert response.json()["ocr"]["available"] is ocr_result["available"]
    assert response.json()["ocr"]["error"] is not None


def test_edited_image_text_uses_image_ocr_analysis_contract(auth_client, monkeypatch):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    captured = {}

    def fake_analysis(**kwargs):
        captured.update(kwargs)
        return {
            "source_type": "Image OCR",
            "extraction_status": "success",
            "has_sufficient_evidence": True,
            "final_verdict": "MEDIUM RISK",
            "final_score": 40,
            "risk_score": 40,
            "risk_level": "MEDIUM RISK",
            "rule_score": 40,
            "rule_level": "Medium",
            "matched_categories": ["financial solicitation"],
            "evidence": ["OCR credential request matched"],
            "explanation": "Reviewed OCR text was evaluated.",
            "recommendation": "Review the source.",
            "investigation_status": "Reviewing",
            "review_required": True,
            "consensus_status": "Conservative Review",
            "engine_status": {"rules": "available", "tfidf": "unavailable", "distilbert": "unavailable"},
            "ml_prediction": None,
            "ml_confidence": None,
            "hf_prediction": None,
            "hf_confidence": None,
        }

    monkeypatch.setattr(api_module, "run_unified_analysis", fake_analysis)
    response = auth_client.post(
        "/api/analyze-image-text",
        headers={"X-CSRF-Token": csrf},
        json={"text": "Corrected advertisement text"},
    )
    assert response.status_code == 200
    assert captured == {"text": "Corrected advertisement text", "source_type": "Image OCR"}
    assert response.json()["final_verdict"] == "MEDIUM RISK"
    assert response.json()["evidence"] == ["OCR credential request matched"]


def test_pdf_endpoint_requires_auth_and_csrf(auth_client):
    response = auth_client.post(
        "/api/document/pdf",
        files={"document": ("brief.pdf", b"%PDF-1.7", "application/pdf")},
    )
    assert response.status_code == 401

    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    response = auth_client.post(
        "/api/document/pdf",
        files={"document": ("brief.pdf", b"%PDF-1.7", "application/pdf")},
    )
    assert response.status_code == 403


def test_pdf_extraction_returns_bounded_metadata_and_text(auth_client, monkeypatch):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    monkeypatch.setattr(
        api_module,
        "extract_pdf_text",
        lambda upload: {
            "valid": True,
            "text": "Extracted PDF advertisement",
            "error": None,
            "warnings": ["bounded warning"],
            "metadata": {
                "total_pages": 2,
                "pages_extracted": 2,
                "size_kb": 4.0,
                "characters_extracted": 28,
                "title": "private title must not leak",
                "author": "private author must not leak",
            },
        },
    )
    response = auth_client.post(
        "/api/document/pdf",
        headers={"X-CSRF-Token": csrf},
        files={"document": ("brief.pdf", b"%PDF-1.7 safe fixture", "application/pdf")},
    )
    assert response.status_code == 200
    assert response.json()["text"] == "Extracted PDF advertisement"
    assert response.json()["metadata"] == {
        "total_pages": 2,
        "pages_extracted": 2,
        "size_kb": 4.0,
        "characters_extracted": 28,
    }
    assert "private title" not in response.text


def test_docx_malformed_and_oversized_documents_are_rejected_safely(auth_client):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    headers = {"X-CSRF-Token": csrf}
    malformed = auth_client.post(
        "/api/document/docx",
        headers=headers,
        files={
            "document": (
                "brief.docx",
                b"not-a-docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
        },
    )
    assert malformed.status_code == 200
    assert malformed.json()["valid"] is False
    assert malformed.json()["error"] == "Document is malformed or has an unsupported format."

    oversized = auth_client.post(
        "/api/document/docx",
        headers=headers,
        files={
            "document": (
                "brief.docx",
                b"x" * (10 * 1024 * 1024 + 1),
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
        },
    )
    assert oversized.status_code == 200
    assert oversized.json()["valid"] is False
    assert "10 MB" in oversized.json()["error"]


def test_document_content_type_and_extraction_failure_are_safe(auth_client, monkeypatch):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    headers = {"X-CSRF-Token": csrf}
    wrong_type = auth_client.post(
        "/api/document/pdf",
        headers=headers,
        files={"document": ("brief.pdf", b"%PDF-1.7", "application/octet-stream")},
    )
    assert wrong_type.status_code == 422
    assert wrong_type.json() == {"detail": "Unsupported PDF content type."}

    monkeypatch.setattr(
        api_module,
        "extract_docx_text",
        lambda upload: (_ for _ in ()).throw(RuntimeError("private document path")),
    )
    failed = auth_client.post(
        "/api/document/docx",
        headers=headers,
        files={
            "document": (
                "brief.docx",
                b"PK\x03\x04safe fixture",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
        },
    )
    assert failed.status_code == 503
    assert failed.json() == {"detail": "DOCX extraction service unavailable."}
    assert "private document path" not in failed.text


def test_edited_pdf_and_docx_text_use_document_analysis_contract(auth_client, monkeypatch):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    calls = []

    def fake_analysis(**kwargs):
        calls.append(kwargs)
        return {
            "source_type": kwargs["source_type"],
            "extraction_status": "success",
            "has_sufficient_evidence": True,
            "final_verdict": "LOW RISK",
            "final_score": 10,
            "risk_score": 10,
            "risk_level": "LOW RISK",
            "rule_score": 10,
            "rule_level": "Low",
            "matched_categories": [],
            "explanation": "Document text evaluated.",
            "recommendation": "Continue review.",
            "investigation_status": "Reviewing",
            "review_required": False,
            "consensus_status": "Consensus Benign / Safe",
            "engine_status": {"rules": "available", "tfidf": "unavailable", "distilbert": "unavailable"},
            "ml_prediction": None,
            "ml_confidence": None,
            "hf_prediction": None,
            "hf_confidence": None,
        }

    monkeypatch.setattr(api_module, "run_unified_analysis", fake_analysis)
    for endpoint, source_type in (
        ("/api/analyze-pdf-text", "PDF Document"),
        ("/api/analyze-docx-text", "DOCX Document"),
    ):
        response = auth_client.post(
            endpoint,
            headers={"X-CSRF-Token": csrf},
            json={"text": "Corrected document advertisement"},
        )
        assert response.status_code == 200
        assert response.json()["source_type"] == source_type
    assert calls == [
        {"text": "Corrected document advertisement", "source_type": "PDF Document"},
        {"text": "Corrected document advertisement", "source_type": "DOCX Document"},
    ]


def test_pdf_text_analysis_returns_computed_score_and_evidence(auth_client, monkeypatch):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    suspicious_text = (
        "Guaranteed monthly earnings. Rent out a bank account for transfers. "
        "Send bank login credentials and OTP. Pay an advance activation fee. "
        "Forward incoming transfers and avoid contacting the bank."
    )
    captured = {}

    def fake_analysis(**kwargs):
        captured.update(kwargs)
        return {
            "source_type": "PDF Document",
            "extraction_status": "success",
            "has_sufficient_evidence": True,
            "final_verdict": "HIGH RISK",
            "final_score": 55,
            "risk_score": 55,
            "risk_level": "HIGH RISK",
            "rule_score": 55,
            "rule_level": "High",
            "matched_categories": ["Account Rental & Mule Recruitment", "Suspicious Financial Solicitation"],
            "evidence": [
                '[Account Rental & Mule Recruitment] Solicitation: "Rent out a bank account"',
                '[Suspicious Financial Solicitation] Credential request: "bank login credentials and OTP"',
            ],
            "explanation": "Rule indicators detected.",
            "recommendation": "Review.",
            "investigation_status": "Open",
            "review_required": True,
            "consensus_status": "Rule Violation (Model Divergence)",
            "engine_status": {"rules": "available", "tfidf": "unavailable", "distilbert": "unavailable"},
            "ml_prediction": None,
            "ml_confidence": None,
            "hf_prediction": None,
            "hf_confidence": None,
        }

    monkeypatch.setattr(api_module, "run_unified_analysis", fake_analysis)
    response = auth_client.post(
        "/api/analyze-pdf-text",
        headers={"X-CSRF-Token": csrf},
        json={"text": suspicious_text},
    )

    assert response.status_code == 200
    payload = response.json()
    assert captured == {"text": suspicious_text, "source_type": "PDF Document"}
    assert payload["final_score"] == 55
    assert payload["risk_score"] == 55
    assert payload["matched_categories"]
    assert payload["evidence"]


def test_csv_analysis_requires_session_and_csrf(auth_client):
    payload = {"csv_file": ("ads.csv", b"text\nexample advertisement\n", "text/csv")}
    assert auth_client.post("/api/analyze-csv", files=payload, data={"text_column": "text"}).status_code == 401

    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    response = auth_client.post(
        "/api/analyze-csv",
        files=payload,
        data={"text_column": "text"},
    )
    assert response.status_code == 403
    assert response.json() == {"detail": "CSRF validation failed."}


def test_csv_analysis_returns_bounded_rows_and_sanitized_export(auth_client, monkeypatch):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200

    monkeypatch.setattr(
        api_module,
        "run_batch_analysis",
        lambda **kwargs: pd.DataFrame([
            {
                "row_index": 0,
                "original_text": "=SUM(1,1)",
                "final_verdict": None,
                "final_score": None,
                "risk_score": None,
                "risk_level": None,
                "rule_score": None,
                "rule_level": None,
                "matched_categories": "",
                "tfidf_status": "unavailable",
                "distilbert_status": "unavailable",
                "recommendation": "Text insufficient or empty",
                "investigation_status": None,
                "review_required": None,
                "validation_status": "INVALID: Text too short or empty",
                "ground_truth": "bad",
            },
            {
                "row_index": 1,
                "original_text": "Legitimate advertisement",
                "final_verdict": "LOW RISK",
                "final_score": 10,
                "risk_score": 10,
                "risk_level": "Low",
                "rule_score": 10,
                "rule_level": "Low",
                "matched_categories": "",
                "tfidf_status": "unavailable",
                "distilbert_status": "unavailable",
                "recommendation": "Continue review.",
                "investigation_status": "Reviewing",
                "review_required": False,
                "validation_status": "OK",
                "ground_truth": "good",
            },
        ]),
    )

    response = auth_client.post(
        "/api/analyze-csv",
        headers={"X-CSRF-Token": csrf},
        files={"csv_file": ("ads.csv", b'text,label\n"=SUM(1,1)",bad\nLegitimate advertisement,good\n', "text/csv")},
        data={"text_column": "text", "label_column": "label", "include_hf": "false"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is True
    assert body["row_count"] == 2
    assert body["summary"] == {
        "total_rows": 2,
        "successful_rows": 1,
        "invalid_rows": 1,
        "failed_rows": 0,
        "skipped_rows": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 1,
        "unscored_count": 1,
    }
    assert body["results"][0]["distilbert_status"] == "unavailable"
    assert "\t=SUM(1,1)" in body["export_csv"]
    assert "tfidf_error" not in body["export_csv"]


def test_csv_analysis_rejects_invalid_columns_and_reports_limits(auth_client, monkeypatch):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    headers = {"X-CSRF-Token": csrf}

    missing_column = auth_client.post(
        "/api/analyze-csv",
        headers=headers,
        files={"csv_file": ("ads.csv", b"text\nvalid advertisement\n", "text/csv")},
        data={"text_column": "missing"},
    )
    assert missing_column.status_code == 422
    assert missing_column.json() == {"detail": "Selected text column was not found in the CSV."}

    monkeypatch.setattr(api_module, "MAX_ROWS", 1)
    too_many = auth_client.post(
        "/api/analyze-csv",
        headers=headers,
        files={"csv_file": ("ads.csv", b"text\nfirst\nsecond\n", "text/csv")},
        data={"text_column": "text"},
    )
    assert too_many.status_code == 200
    assert too_many.json()["valid"] is False
    assert "Maximum: 1 rows" in too_many.json()["error"]

    monkeypatch.setattr(api_module, "MAX_SIZE_MB", 0.000001)
    too_large = auth_client.post(
        "/api/analyze-csv",
        headers=headers,
        files={"csv_file": ("ads.csv", b"text\nvalid advertisement\n", "text/csv")},
        data={"text_column": "text"},
    )
    assert too_large.status_code == 200
    assert too_large.json()["valid"] is False
    assert "File too large" in too_large.json()["error"]


def test_csv_analysis_failure_is_safe(auth_client, monkeypatch):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    monkeypatch.setattr(api_module, "run_batch_analysis", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("private path")))
    response = auth_client.post(
        "/api/analyze-csv",
        headers={"X-CSRF-Token": csrf},
        files={"csv_file": ("ads.csv", b"text\nvalid advertisement\n", "text/csv")},
        data={"text_column": "text"},
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "CSV analysis service unavailable."}
    assert "private path" not in response.text


def test_investigations_require_authentication(auth_client):
    response = auth_client.get("/api/investigations")
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required."}


def test_investigation_search_and_detail_are_safe_projections(auth_client, monkeypatch):
    record = {
        "record_id": "TF-CASE123",
        "ad_text": "Suspicious investment advertisement with contact detail",
        "risk_score": 82,
        "risk_level": "Critical",
        "investigation_status": "Open",
        "submitted_at": "2026-10-23T12:00:00+00:00",
        "analysis_mode": "rule_based",
        "review_required": 1,
        "review_recommendation": "Escalate for review.",
        "matched_categories": ["credential_harvesting"],
        "urls": ["https://example.invalid"],
        "emails": ["review@example.invalid"],
        "phone_numbers": [],
        "payment_identifiers": [],
        "ml_prediction": None,
        "ml_confidence": None,
        "hf_prediction": None,
        "hf_confidence": None,
        "evidence": ["must not be exposed by the API projection"],
    }
    monkeypatch.setattr(api_module, "search_records", lambda **kwargs: [record])
    monkeypatch.setattr(api_module, "get_record", lambda record_id: record if record_id == "TF-CASE123" else None)
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200

    listing = auth_client.get("/api/investigations?query=credential&risk_level=Critical&status=Open")
    assert listing.status_code == 200
    assert listing.json()["count"] == 1
    assert listing.json()["items"][0]["record_id"] == "TF-CASE123"
    assert "evidence" not in listing.text

    detail = auth_client.get("/api/investigations/TF-CASE123")
    assert detail.status_code == 200
    assert detail.json()["ad_text"] == record["ad_text"]
    assert detail.json()["matched_categories"] == ["credential_harvesting"]
    assert "evidence" not in detail.text


def test_investigation_filters_and_missing_record_are_validated(auth_client, monkeypatch):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    monkeypatch.setattr(api_module, "search_records", lambda **kwargs: [])

    invalid_risk = auth_client.get("/api/investigations?risk_level=Unknown")
    assert invalid_risk.status_code == 422
    assert invalid_risk.json() == {"detail": "Unsupported investigation risk level."}
    invalid_status = auth_client.get("/api/investigations?status=Archived")
    assert invalid_status.status_code == 422
    assert invalid_status.json() == {"detail": "Unsupported investigation status."}

    monkeypatch.setattr(api_module, "get_record", lambda record_id: None)
    missing = auth_client.get("/api/investigations/TF-MISSING")
    assert missing.status_code == 404
    assert missing.json() == {"detail": "Investigation record not found."}


def test_investigation_status_requires_csrf_validates_lifecycle_and_persists(auth_client, monkeypatch):
    record = {
        "record_id": "TF-CASE123", "ad_text": "Advertisement", "risk_score": 50,
        "risk_level": "High", "investigation_status": "Reviewing",
        "submitted_at": "2026-10-23T12:00:00+00:00", "analysis_mode": "rule_based",
        "review_required": True, "review_recommendation": "Review.",
        "matched_categories": [], "urls": [], "emails": [], "phone_numbers": [],
        "payment_identifiers": [], "ml_prediction": None, "ml_confidence": None,
        "hf_prediction": None, "hf_confidence": None,
    }
    calls = []
    def fake_update_status(record_id, status):
        calls.append((record_id, status))
        record["investigation_status"] = status
        return True
    monkeypatch.setattr(api_module, "update_status", fake_update_status)
    monkeypatch.setattr(api_module, "get_record", lambda record_id: record)
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200

    missing_csrf = auth_client.patch("/api/investigations/TF-CASE123/status", json={"status": "Closed"})
    assert missing_csrf.status_code == 403
    invalid = auth_client.patch(
        "/api/investigations/TF-CASE123/status",
        headers={"X-CSRF-Token": csrf},
        json={"status": "Archived"},
    )
    assert invalid.status_code == 422
    assert calls == []

    updated = auth_client.patch(
        "/api/investigations/TF-CASE123/status",
        headers={"X-CSRF-Token": csrf},
        json={"status": "Closed"},
    )
    assert updated.status_code == 200
    assert calls == [("TF-CASE123", "Closed")]
    assert updated.json()["status"] == "Closed"


def test_evidence_vault_requires_authentication_and_handles_missing_records(auth_client):
    response = auth_client.get("/api/evidence/TF-MISSING")
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required."}

    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    invalid = auth_client.get("/api/evidence/../bad")
    assert invalid.status_code in {404, 422}


def test_evidence_graph_returns_redacted_allowlisted_relationships(auth_client, monkeypatch):
    record = {
        "record_id": "TF-EVID123", "ad_text": "Suspicious advertisement",
        "analysis_mode": "rule_based", "risk_score": 75,
        "evidence": ["private raw evidence must not be returned"],
        "urls": ["https://example.invalid"], "phone_numbers": [],
    }
    monkeypatch.setattr(api_module, "get_record", lambda record_id: record)
    monkeypatch.setattr(api_module, "get_all_records", lambda: [record])
    monkeypatch.setattr(
        api_module,
        "build_evidence_graph",
        lambda *args, **kwargs: {
            "central_id": "advertisement-central",
            "classification": "HIGH RISK",
            "risk_score": 75,
            "evidence_count": 1,
            "high_risk_count": 1,
            "advertisement_result": {"evidence": record["evidence"]},
            "nodes": [
                {"id": "advertisement-central", "type": "advertisement", "label": "Advertisement", "value": "Redacted advertisement", "source": "rule_based", "reason": "Stored analysis", "risk": "high", "confidence": None, "related_ids": ["url-1"]},
                {"id": "url-1", "type": "url", "label": "Advertisement URL", "value": "https://example.invalid", "source": "Advertisement text", "reason": "Observed URL", "risk": "medium", "confidence": None, "related_ids": ["advertisement-central"]},
            ],
            "edges": [{"source": "advertisement-central", "target": "url-1", "label": "contains"}],
        },
    )
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200

    response = auth_client.get("/api/evidence/TF-EVID123")
    assert response.status_code == 200
    body = response.json()
    assert body["record_id"] == "TF-EVID123"
    assert body["edges"] == [{"source": "advertisement-central", "target": "url-1", "label": "contains"}]
    assert "advertisement_result" not in response.text
    assert "private raw evidence" not in response.text


def test_evidence_graph_service_failure_is_safe(auth_client, monkeypatch):
    monkeypatch.setattr(api_module, "get_record", lambda record_id: {"record_id": record_id, "ad_text": "Advertisement"})
    monkeypatch.setattr(api_module, "build_evidence_graph", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("private path")))
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    response = auth_client.get("/api/evidence/TF-EVID123")
    assert response.status_code == 503
    assert response.json() == {"detail": "Evidence data unavailable."}
    assert "private path" not in response.text


def test_records_report_requires_authentication_and_supports_filters(auth_client, monkeypatch):
    response = auth_client.get("/api/reports/records")
    assert response.status_code == 401

    records = [
        {
            "record_id": "TF-REPORT1", "ad_text": "=SUM(1,1)", "risk_score": 85,
            "risk_level": "Critical", "investigation_status": "Open",
            "submitted_at": "2026-10-23T12:00:00+00:00", "analysis_mode": "rule_based",
            "review_required": 1, "review_recommendation": "Escalate.",
            "matched_categories": ["credential_harvesting"], "urls": [], "emails": [],
            "phone_numbers": [], "payment_identifiers": [], "ml_prediction": None,
            "ml_confidence": None, "is_synthetic": False,
        },
        {
            "record_id": "TF-REPORT2", "ad_text": "Legitimate notice", "risk_score": 10,
            "risk_level": "Low", "investigation_status": "Closed",
            "submitted_at": "2026-10-22T12:00:00+00:00", "analysis_mode": "rule_based",
            "review_required": 0, "review_recommendation": "No immediate review.",
            "matched_categories": [], "urls": [], "emails": [], "phone_numbers": [],
            "payment_identifiers": [], "ml_prediction": "Safe", "ml_confidence": 0.9,
            "is_synthetic": False,
        },
    ]
    monkeypatch.setattr(api_module, "search_records", lambda **kwargs: records)
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200

    report = auth_client.get("/api/reports/records?risk_level=Critical&status=Open&limit=1")
    assert report.status_code == 200
    body = report.json()
    assert body["summary"] == {
        "total_matching": 2,
        "returned": 1,
        "truncated": True,
        "risk_counts": {"Critical": 1, "Low": 1},
        "status_counts": {"Open": 1, "Closed": 1},
    }
    assert body["records"][0]["record_id"] == "TF-REPORT1"
    assert "\t=SUM(1,1)" in body["export_csv"]
    assert "evidence" not in report.text


def test_records_report_validates_filters_and_handles_empty_data(auth_client, monkeypatch):
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    monkeypatch.setattr(api_module, "search_records", lambda **kwargs: [])

    invalid_risk = auth_client.get("/api/reports/records?risk_level=Unknown")
    assert invalid_risk.status_code == 422
    assert invalid_risk.json() == {"detail": "Unsupported report risk level."}
    invalid_status = auth_client.get("/api/reports/records?status=Archived")
    assert invalid_status.status_code == 422
    assert invalid_status.json() == {"detail": "Unsupported report status."}

    empty = auth_client.get("/api/reports/records")
    assert empty.status_code == 200
    assert empty.json()["summary"]["total_matching"] == 0
    assert empty.json()["records"] == []
    assert empty.json()["export_csv"] is None


def test_records_report_failure_is_safe(auth_client, monkeypatch):
    monkeypatch.setattr(api_module, "search_records", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("private report path")))
    csrf = csrf_for(auth_client)
    assert login_for(auth_client, csrf).status_code == 200
    response = auth_client.get("/api/reports/records")
    assert response.status_code == 503
    assert response.json() == {"detail": "Report data unavailable."}
    assert "private report path" not in response.text
