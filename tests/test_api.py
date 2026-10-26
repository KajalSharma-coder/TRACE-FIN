from fastapi.testclient import TestClient

import pytest

import backend.api.main as api_module
from backend.api.main import app


client = TestClient(app)


@pytest.fixture(autouse=True)
def authenticated_analysis_request():
    app.dependency_overrides[api_module._require_authenticated_user] = lambda: {
        "id": 1,
        "name": "Test Analyst",
        "email": "analyst@example.org",
    }
    client.cookies.set(api_module.CSRF_COOKIE_NAME, "test-csrf", path="/")
    yield
    app.dependency_overrides.clear()
    client.cookies.clear()


def analysis_headers():
    return {"X-CSRF-Token": "test-csrf"}


def test_health_endpoint_is_minimal_and_safe():
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "trace-fin-api"}


def test_analysis_endpoint_delegates_to_existing_service_and_preserves_statuses(monkeypatch):
    captured = {}

    def fake_analysis(**kwargs):
        captured.update(kwargs)
        return {
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
            "explanation": "Explicitly supplied test result.",
            "recommendation": "Escalate for review.",
            "investigation_status": "Escalated",
            "review_required": True,
            "consensus_status": "Consensus Threat",
            "engine_status": {
                "rules": "available",
                "tfidf": "unavailable",
                "distilbert": "unavailable",
            },
            "engine_errors": {"distilbert": "C:\\private\\checkpoint"},
            "analyzed_text": "secret input",
            "evidence": ["sensitive evidence"],
            "ml_prediction": "scam",
            "ml_confidence": 0.9,
            "hf_prediction": None,
            "hf_confidence": None,
        }

    monkeypatch.setattr("backend.api.main.run_unified_analysis", fake_analysis)
    response = client.post("/api/analyze", headers=analysis_headers(), json={"text": "test advertisement"})

    assert response.status_code == 200
    assert captured == {"text": "test advertisement", "source_type": "Direct Text"}
    payload = response.json()
    assert payload["final_verdict"] == "HIGH RISK"
    assert payload["engine_status"]["distilbert"] == "unavailable"
    assert "analyzed_text" not in payload
    assert payload["evidence"] == ["sensitive evidence"]
    assert "engine_errors" not in payload


def test_analysis_validation_rejects_oversized_input_without_calling_service(monkeypatch):
    called = False

    def unexpected_call(**kwargs):
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr("backend.api.main.run_unified_analysis", unexpected_call)
    response = client.post("/api/analyze", headers=analysis_headers(), json={"text": "x" * 200_001})

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request."}
    assert called is False


def test_analysis_failure_does_not_expose_internal_details(monkeypatch):
    def failing_analysis(**kwargs):
        raise RuntimeError("C:\\private\\tracefin.db and secret token")

    monkeypatch.setattr("backend.api.main.run_unified_analysis", failing_analysis)
    response = client.post("/api/analyze", headers=analysis_headers(), json={"text": "test"})

    assert response.status_code == 503
    assert response.json() == {"detail": "Analysis service unavailable."}
    assert "tracefin.db" not in response.text


def test_cors_is_narrow_and_allows_credentials_for_trusted_origin():
    response = client.options(
        "/api/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert response.headers["access-control-allow-credentials"] == "true"


def test_cors_rejects_untrusted_origin():
    response = client.options(
        "/api/auth/session",
        headers={
            "Origin": "https://untrusted.example",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers
