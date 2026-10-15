import os
import re
import sys
from pathlib import Path
import pytest

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import DATASET_PATH
from src.hf_model import (
    check_hf_dependencies,
    prepare_dataset,
    predict_ad_hf,
    get_hf_model_info,
    get_hf_model_status,
    _normalize_ad_text,
    _extract_template_fingerprint,
    EXCLUDED_COLUMNS,
    HF_BASE_MODEL,
    LABEL_MAP,
)


def test_check_hf_dependencies():
    deps = check_hf_dependencies()
    assert isinstance(deps, dict)
    assert "available" in deps
    assert "torch_available" in deps
    assert "transformers_available" in deps
    assert "cuda_available" in deps
    assert "device" in deps


def test_template_fingerprinting():
    # Identical templates with differing account numbers should yield the same fingerprint
    t1 = "Selling fully KYC verified HDFC account. Acc: 66562328946, IFSC: HDFC0437589"
    t2 = "Selling fully KYC verified HDFC account. Acc: 11223344556, IFSC: HDFC0999999"
    fp1 = _extract_template_fingerprint(t1)
    fp2 = _extract_template_fingerprint(t2)
    assert fp1 == fp2
    assert len(fp1) > 0


def test_template_fingerprinting_normalizes_holder_names():
    t1 = "Selling bank account. Account holder: Ananya Sharma. Ready for use"
    t2 = "Selling bank account. Account holder: Rahul Verma. Ready for use"
    assert _extract_template_fingerprint(t1, ["Ananya Sharma"]) == _extract_template_fingerprint(
        t2, ["Rahul Verma"]
    )


def test_hf_preprocessing_redacts_identifiers_consistently():
    text = "Account holder Ananya Sharma, account 61641030277, IFSC ICIC0475599"
    normalized = _normalize_ad_text(text, ["Ananya Sharma"])
    assert "Ananya Sharma" not in normalized
    assert "61641030277" not in normalized
    assert "ICIC0475599" not in normalized
    assert "<PERSON>" in normalized
    assert "<ACCOUNT_NUM>" in normalized
    assert "<IFSC_CODE>" in normalized


def test_prepare_dataset_handles_conflicting_template_groups_without_empty_splits(tmp_path):
    import pandas as pd

    rows = []
    number_words = ("one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve")
    for label, token in (("Safe", "legitimate"), ("High Risk", "fraudulent")):
        for index, number_word in enumerate(number_words):
            rows.append({
                "Advertisement_Text": f"case{number_word} {token} financial message template offer",
                "Risk_Label": label,
            })
    # Same first 35 normalized characters, conflicting labels: must stay grouped.
    rows.extend([
        {"Advertisement_Text": "shared ambiguous template prefix with the same neutral wording safe", "Risk_Label": "Safe"},
        {"Advertisement_Text": "shared ambiguous template prefix with the same neutral wording scam", "Risk_Label": "High Risk"},
    ])
    path = tmp_path / "mixed.csv"
    pd.DataFrame(rows).to_csv(path, index=False)

    result = prepare_dataset(path, random_state=7)
    assert result["train_texts"] and result["val_texts"] and result["test_texts"]
    assert set(result["template_groups"]["train"]).isdisjoint(result["template_groups"]["val"])
    assert set(result["template_groups"]["train"]).isdisjoint(result["template_groups"]["test"])
    assert set(result["template_groups"]["val"]).isdisjoint(result["template_groups"]["test"])
    assert any("mixed labels" in warning.lower() for warning in result["warnings"])


def test_prepare_dataset_schema_and_pii_exclusion():
    if not DATASET_PATH.exists():
        pytest.skip(f"Dataset not found at {DATASET_PATH}")

    data = prepare_dataset(DATASET_PATH, test_size=0.2, val_size=0.1, random_state=42)

    assert "train_texts" in data
    assert "train_labels" in data
    assert "val_texts" in data
    assert "val_labels" in data
    assert "test_texts" in data
    assert "test_labels" in data
    assert data["template_count"] >= 4

    # Verify no PII leaked into labels or text representations
    total_samples = len(data["train_texts"]) + len(data["val_texts"]) + len(data["test_texts"])
    assert total_samples == 500

    # Class balance check
    dist = data["class_distribution"]["total"]
    assert dist["High Risk"] == 253
    assert dist["Safe"] == 247
    # Each partition must contain examples of both labels; a one-class
    # validation set cannot support meaningful model selection.
    for split in ("train", "val", "test"):
        labels = data[f"{split}_labels"]
        assert set(labels) == {0, 1}
        split_texts = data[f"{split}_texts"]
        assert any("<PERSON>" in text for text in split_texts)
        assert all(not re.search(r"\b\d{4,}\b", text) for text in split_texts)
    groups = data["template_groups"]
    assert set(groups["train"]).isdisjoint(groups["val"])
    assert set(groups["train"]).isdisjoint(groups["test"])
    assert set(groups["val"]).isdisjoint(groups["test"])


def test_hf_model_status_reports_artifact_and_training_evidence():
    status = get_hf_model_status()
    assert {"available", "trained", "loaded", "status", "label_mapping_valid"} <= set(status)
    if status["available"]:
        assert status["label_mapping_valid"] is True
    if status["trained"]:
        assert status["base_model"]
        assert status["trained_at"]
    if status["trained"] and not status.get("trained_for_scam_ads"):
        assert "unverified" in status["status"].lower()


def test_hf_model_status_rejects_mismatched_label_mapping(tmp_path, monkeypatch):
    import json
    import src.hf_model as hf_module

    model_dir = tmp_path / "bad-label-model"
    model_dir.mkdir()
    (model_dir / "config.json").write_text(
        json.dumps({"id2label": {"0": "positive", "1": "negative"}}),
        encoding="utf-8",
    )
    (model_dir / "model.safetensors").write_bytes(b"weights")
    (model_dir / "tokenizer.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(hf_module, "HF_MODEL_DIR", model_dir)
    monkeypatch.setattr(hf_module, "HF_METADATA_PATH", model_dir / "metadata.json")

    status = get_hf_model_status()
    assert status["available"] is False
    assert status["label_mapping_valid"] is False
    assert "label" in status["error"].lower()


def test_predict_ad_hf_empty_input():
    res = predict_ad_hf("")
    assert res["available"] is False
    assert "empty" in res["error"].lower()

    res_spaces = predict_ad_hf("   ")
    assert res_spaces["available"] is False
    assert "empty" in res_spaces["error"].lower()


def test_predict_ad_hf_structure():
    # If model is not yet fine-tuned, it should return available=False with clean error message
    res = predict_ad_hf("Selling bank account without verification")
    assert isinstance(res, dict)
    assert "available" in res
    assert "risk_label" in res
    assert "confidence" in res
    assert "disclaimer" in res
    assert isinstance(res["disclaimer"], str)
    if res["available"]:
        assert set(res["class_probabilities"]) == {"Safe", "High Risk"}
        assert abs(sum(res["class_probabilities"].values()) - 1.0) < 0.01
        assert res["high_risk_score"] == res["class_probabilities"]["High Risk"]
        long_res = predict_ad_hf("Legitimate loan terms and repayment information. " * 500)
        assert long_res["available"] is True
        assert long_res["token_count"] <= long_res["max_length"] == 128


def test_get_hf_model_info():
    info = get_hf_model_info()
    # Either None (if not trained) or dict with metadata
    assert info is None or isinstance(info, dict)
