"""
TRACE//FIN — Phase 3 Machine Learning Test Suite
Tests dataset integrity, token preprocessing, ML pipeline training, artifact persistence,
inference API, edge cases, dual-engine consensus, and database compatibility.
"""

from pathlib import Path
import pytest
import pandas as pd

from config import DATASET_PATH, SPAM_DATASET_PATH, MODEL_PATH, METRICS_PATH
from src.ml_model import (
    preprocess_text,
    train_model,
    predict_ad_ml,
    compare_rule_and_ml,
    load_model,
    get_model_metrics,
    EXCLUDED_COLUMNS,
)
from src.database import init_db, insert_record, get_record, generate_record_id


# ── 1. Text Preprocessing Tests ────────────────────────────────────────

def test_preprocess_text_normalizes_identifiers():
    """Ensure specific bank account numbers and IFSC codes are replaced with generic tokens."""
    sample = "Pay into Account: 49070386820 IFSC: ICIC0755396 via seller@okaxis"
    cleaned = preprocess_text(sample)

    # Identifiers should be tokenized
    assert "49070386820" not in cleaned
    assert "icic0755396" not in cleaned
    assert "<account_num>" in cleaned
    assert "<ifsc_code>" in cleaned
    assert "<upi_handle>" in cleaned


def test_preprocess_text_preserves_crime_semantics():
    """Ensure criminal vernacular words are preserved for TF-IDF feature extraction."""
    sample = "Selling fully KYC verified bank account with ATM card for 10k/month hawala transfer"
    cleaned = preprocess_text(sample)

    assert "selling" in cleaned
    assert "kyc" in cleaned
    assert "verified" in cleaned
    assert "bank" in cleaned
    assert "account" in cleaned
    assert "hawala" in cleaned
    assert "<rental_amount>" in cleaned


def test_preprocess_empty_and_invalid_inputs():
    """Ensure preprocessor handles empty, None, and non-string inputs safely."""
    assert preprocess_text("") == ""
    assert preprocess_text("   ") == ""
    assert preprocess_text(None) == ""
    assert preprocess_text(12345) == ""


# ── 2. Dataset Integrity & Isolation Tests ─────────────────────────────

def test_primary_dataset_schema_and_distribution():
    """Validate back.dataset.csv exists, has required columns, and clean class distribution."""
    assert DATASET_PATH.exists(), f"Primary dataset missing at {DATASET_PATH}"
    df = pd.read_csv(DATASET_PATH)

    assert "Advertisement_Text" in df.columns
    assert "Risk_Label" in df.columns
    assert len(df) == 500

    # Ensure prohibited identifier columns are identified
    for col in EXCLUDED_COLUMNS:
        assert col in df.columns

    # Check target classes
    labels = set(df["Risk_Label"].unique())
    assert labels == {"Safe", "High Risk"}
    assert df["Risk_Label"].value_counts()["High Risk"] == 253
    assert df["Risk_Label"].value_counts()["Safe"] == 247


def test_spam_dataset_isolation():
    """Confirm cleaned_spam_dataset.csv exists but is kept separate from primary training."""
    assert SPAM_DATASET_PATH.exists()
    df_spam = pd.read_csv(SPAM_DATASET_PATH)

    # Confirm it has spam SMS schema
    assert "label" in df_spam.columns
    assert "message" in df_spam.columns
    assert set(df_spam["label"].unique()) == {"ham", "spam"}

    # Ensure it has not been merged into back.dataset.csv
    df_primary = pd.read_csv(DATASET_PATH)
    assert "ham" not in df_primary["Risk_Label"].unique()
    assert "spam" not in df_primary["Risk_Label"].unique()


# ── 3. Model Training & Artifact Persistence ───────────────────────────

def test_train_model_generates_artifacts(tmp_path):
    """Verify train_model trains reproducible pipeline and writes artifacts."""
    custom_model = tmp_path / "test_model.joblib"
    custom_metrics = tmp_path / "test_metrics.json"

    metrics = train_model(
        dataset_path=DATASET_PATH,
        model_path=custom_model,
        metrics_path=custom_metrics,
        random_state=42,
        test_size=0.2,
    )

    assert custom_model.exists()
    assert custom_metrics.exists()

    # Check metrics structure
    assert metrics["total_samples"] == 500
    assert metrics["train_samples"] + metrics["validation_samples"] + metrics["test_samples"] == 500
    assert metrics["template_count"] == 8
    assert metrics["train_samples"] == 254
    assert metrics["validation_samples"] == 114
    assert metrics["test_samples"] == 132
    assert metrics["class_distribution"]["val"] == {"Safe": 51, "High Risk": 63}
    assert "false_negative_rate" in metrics
    assert "accuracy" in metrics
    assert "classification_report" in metrics
    assert "confusion_matrix" in metrics
    assert len(metrics["top_features"]["high_risk_signals"]) > 0
    assert len(metrics["top_features"]["safe_signals"]) > 0
    assert len(metrics["limitations"]) > 0


# ── 4. Inference API Tests ─────────────────────────────────────────────

def test_predict_ad_ml_high_risk():
    """Test ML prediction on known high-risk ad template."""
    text = "Selling fully KYC verified HDFC account. Call now. Acc holder: Rohan Singh, 94523825656"
    res = predict_ad_ml(text)

    assert res["available"] is True
    assert res["risk_label"] == "High Risk"
    assert res["prediction"] == 1
    assert res["high_risk_score"] > 0.5
    assert res["confidence"] >= 0.5
    assert res["model_version"] is not None
    assert len(res["top_signals"]) > 0
    assert "not calibrated" in res["disclaimer"].lower()


def test_predict_ad_ml_safe():
    """Test ML prediction on known safe transaction template."""
    text = "Donation accepted here. Rohan Patel, Account: 49070386820, IFSC: ICIC0755396. Thank you."
    res = predict_ad_ml(text)

    assert res["available"] is True
    assert res["risk_label"] == "Safe"
    assert res["prediction"] == 0
    assert res["high_risk_score"] < 0.5
    assert res["confidence"] >= 0.5


def test_predict_ad_ml_empty_input():
    """Test ML prediction on empty or whitespace text."""
    res_empty = predict_ad_ml("")
    assert res_empty["available"] is False
    assert res_empty["risk_label"] is None
    assert "empty" in res_empty["error"].lower()

    res_space = predict_ad_ml("    ")
    assert res_space["available"] is False


def test_predict_ad_ml_missing_model_fallback():
    """Test graceful fallback when model artifact file is missing."""
    non_existent = Path("/tmp/non_existent_model_dir_xyz/model.joblib")
    res = predict_ad_ml("test text", model_path=non_existent)

    assert res["available"] is False
    assert res["risk_label"] is None
    assert "not found" in res["error"].lower()


# ── 5. Dual-Engine Consensus Tests ─────────────────────────────────────

def test_compare_rule_and_ml_consensus_threat():
    """Dual engine agreement on high threat."""
    rule_res = {"risk_level": "High", "risk_score": 75}
    ml_res = {"available": True, "risk_label": "High Risk", "confidence_pct": 98.5}

    comp = compare_rule_and_ml(rule_res, ml_res)
    assert comp["is_divergent"] is False
    assert "Consensus: High Risk Threat" in comp["status"]


def test_compare_rule_and_ml_consensus_safe():
    """Dual engine agreement on benign transaction."""
    rule_res = {"risk_level": "Low", "risk_score": 0}
    ml_res = {"available": True, "risk_label": "Safe", "confidence_pct": 95.0}

    comp = compare_rule_and_ml(rule_res, ml_res)
    assert comp["is_divergent"] is False
    assert "Consensus: Benign / Safe" in comp["status"]


def test_compare_rule_and_ml_divergence_rule_alert():
    """Rule engine detects threat that ML missed (out-of-distribution phrasing)."""
    rule_res = {"risk_level": "Critical", "risk_score": 90}
    ml_res = {"available": True, "risk_label": "Safe", "confidence_pct": 60.0}

    comp = compare_rule_and_ml(rule_res, ml_res)
    assert comp["is_divergent"] is True
    assert "Rule Engine Alert" in comp["status"]


def test_compare_rule_and_ml_divergence_ml_alert():
    """ML flags statistical anomaly when rules did not trigger."""
    rule_res = {"risk_level": "Low", "risk_score": 10}
    ml_res = {"available": True, "risk_label": "High Risk", "confidence_pct": 85.0}

    comp = compare_rule_and_ml(rule_res, ml_res)
    assert comp["is_divergent"] is True
    assert "ML Anomaly Alert" in comp["status"]


# ── 6. Database Persistence with ML Fields ─────────────────────────────

def test_database_stores_and_retrieves_ml_fields():
    """Verify SQLite database persists and retrieves ML prediction fields."""
    init_db()
    rec_id = generate_record_id()
    record = {
        "record_id": rec_id,
        "ad_text": "Bank account for sale, bypass KYC verification",
        "analysis_mode": "dual_engine",
        "risk_score": 85.0,
        "risk_level": "Critical",
        "matched_categories": ["Financial Account or Card Sale", "KYC Evasion"],
        "evidence": ["Matched phrase: bank account for sale"],
        "urls": [],
        "emails": [],
        "phone_numbers": [],
        "payment_identifiers": [],
        "review_required": 1,
        "review_recommendation": "Investigator Review Recommended",
        "investigation_status": "Open",
        "is_synthetic": 0,
        "ml_prediction": "High Risk",
        "ml_confidence": 0.9854,
        "ml_high_risk_score": 0.9854,
        "ml_model_version": "tfidf-logreg-v1.0",
    }

    saved_id = insert_record(record)
    assert saved_id == rec_id

    fetched = get_record(rec_id)
    assert fetched is not None
    assert fetched["ml_prediction"] == "High Risk"
    assert abs(fetched["ml_confidence"] - 0.9854) < 1e-4
    assert fetched["ml_model_version"] == "tfidf-logreg-v1.0"
