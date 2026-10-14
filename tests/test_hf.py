import os
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


def test_get_hf_model_info():
    info = get_hf_model_info()
    # Either None (if not trained) or dict with metadata
    assert info is None or isinstance(info, dict)
