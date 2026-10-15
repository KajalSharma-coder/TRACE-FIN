"""Tests for the optional ONNX phishing URL model."""

import numpy as np

from src import url_model


class _Input:
    name = "inputs"


class _Session:
    def get_inputs(self):
        return [_Input()]

    def run(self, _outputs, values):
        assert values["inputs"].tolist() == ["https://example.test/offer"]
        return [None, np.asarray([[0.12, 0.88]], dtype=float)]


def test_classify_url_reads_phishing_probability_from_onnx(monkeypatch):
    monkeypatch.setattr(url_model, "_load_session", lambda: _Session())
    result = url_model.classify_url("https://example.test/offer")
    assert result["available"] is True
    assert result["prediction"] == "Phishing-like"
    assert result["phishing_probability"] == 0.88


def test_classify_url_reports_model_runtime_failure(monkeypatch):
    def fail():
        raise RuntimeError("onnxruntime missing")

    monkeypatch.setattr(url_model, "_load_session", fail)
    result = url_model.classify_url("https://example.test/offer")
    assert result["available"] is False
    assert result["phishing_probability"] is None
    assert "onnxruntime missing" in result["error"]


def test_classify_url_rejects_empty_input():
    result = url_model.classify_url("  ")
    assert result["available"] is False
    assert result["error"]


def test_url_signal_is_evidence_only_and_does_not_change_ad_score(monkeypatch):
    from src import analysis_service

    monkeypatch.setattr(analysis_service, "analyze_ad", lambda _text: {
        "risk_score": 20, "risk_level": "Low", "evidence": [], "urls": ["https://example.test/offer"],
        "matched_rules": [], "matched_categories": [], "emails": [], "phone_numbers": [],
        "payment_identifiers": [],
    })
    monkeypatch.setattr(analysis_service, "predict_ad_ml", lambda _text: {"available": False})
    monkeypatch.setattr(analysis_service, "predict_ad_hf", lambda _text: {"available": False})
    monkeypatch.setattr(analysis_service, "compute_unified_verdict", lambda *_args: {
        "final_score": 20, "final_verdict": "LOW RISK", "explanation": "fixed test",
        "recommendation": "review", "investigation_status": "Reviewing", "review_required": True,
    })
    monkeypatch.setattr(analysis_service, "_classify_urls", lambda _urls: [{
        "available": True, "prediction": "Phishing-like", "phishing_probability": 0.91,
    }])

    result = analysis_service.run_unified_analysis("A sufficiently long sample financial advert")
    assert result["final_score"] == 20
    assert result["final_verdict"] == "LOW RISK"
    assert result["url_model_results"][0]["phishing_probability"] == 0.91
    assert any("does not affect financial-ad risk score" in line for line in result["evidence"])
