"""Regression checks for external data preparation and selected model loading."""

from config import ACTIVE_MODEL_PATH, EXPANDED_MODEL_PATH, MODEL_PATH, MODEL_SELECTION_PATH
from scripts.train_expanded_model import _load_mendeley_splits, redact_identifiers
from src.ml_model import predict_ad_ml


def test_training_redacts_contact_identifiers_but_keeps_url_marker():
    cleaned = redact_identifiers("Call +1 415-555-0199, email risk@example.com, visit https://fraud.test/x")
    assert "+1 415-555-0199" not in cleaned
    assert "risk@example.com" not in cleaned
    assert "https://fraud.test/x" not in cleaned
    assert "<PHONE>" in cleaned
    assert "<EMAIL>" in cleaned
    assert "<URL>" in cleaned


def test_mendeley_splits_are_grouped_and_data_quality_is_reported():
    split, quality = _load_mendeley_splits()
    groups = split["template_groups"]
    assert set(groups["train"]).isdisjoint(groups["val"])
    assert set(groups["train"]).isdisjoint(groups["test"])
    assert set(groups["val"]).isdisjoint(groups["test"])
    assert set(split["train_labels"]) == {0, 1}
    assert set(split["val_labels"]) == {0, 1}
    assert set(split["test_labels"]) == {0, 1}
    assert quality["source_rows"] == 523
    assert quality["exact_duplicate_rows_removed"] == 3
    assert quality["conflicting_template_groups_excluded"] == 1


def test_active_model_is_loadable_and_reports_its_version():
    if ACTIVE_MODEL_PATH == EXPANDED_MODEL_PATH:
        assert MODEL_SELECTION_PATH.is_file()
        expected_version = "tfidf-logreg-expanded-v2"
    else:
        assert ACTIVE_MODEL_PATH == MODEL_PATH
        expected_version = "tfidf-logreg-v1.0"
    result = predict_ad_ml("A financial message asking the recipient to share an OTP")
    assert result["available"] is True
    assert result["model_version"] == expected_version

