import io
import os
import sys
import pandas as pd
import pytest

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.csv_analyzer import (
    validate_csv,
    sanitize_cell,
    run_batch_analysis,
    export_safe_csv,
    _FORMULA_PREFIXES,
)


class MockUploadedCSV:
    """Mock Streamlit UploadedFile for CSV tests."""
    def __init__(self, name: str, content: str, encoding: str = "utf-8"):
        self.name = name
        raw = content.encode(encoding)
        self._io = io.BytesIO(raw)
        self.size = len(raw)

    def read(self, *args, **kwargs):
        return self._io.read(*args, **kwargs)

    def seek(self, *args, **kwargs):
        return self._io.seek(*args, **kwargs)


def test_sanitize_cell_formula_injection():
    # Equals sign
    assert sanitize_cell("=cmd|'/C calc'!A0") == "\t=cmd|'/C calc'!A0"
    # Plus sign
    assert sanitize_cell("+12345") == "\t+12345"
    # Minus sign
    assert sanitize_cell("-SUM(A1:A10)") == "\t-SUM(A1:A10)"
    # At sign
    assert sanitize_cell("@SUM(A1:A10)") == "\t@SUM(A1:A10)"
    # Tab prefix
    assert sanitize_cell("\tSOMETHING") == "\t\tSOMETHING"
    # Normal string
    assert sanitize_cell("Selling KYC account") == "Selling KYC account"
    # Numeric
    assert sanitize_cell(12345) == "12345"
    # None
    assert sanitize_cell(None) == ""


def test_validate_csv_valid():
    csv_text = "Advertisement_Text,Risk_Label\nSelling KYC verified bank account,High Risk\nSalary payment details,Safe\n"
    mock = MockUploadedCSV("ads.csv", csv_text)
    res = validate_csv(mock)
    assert res["valid"] is True
    assert res["row_count"] == 2
    assert "Advertisement_Text" in res["columns"]
    assert "Risk_Label" in res["columns"]


def test_validate_csv_none():
    res = validate_csv(None)
    assert res["valid"] is False
    assert "No file" in res["error"]


def test_validate_csv_empty():
    mock = MockUploadedCSV("empty.csv", "")
    res = validate_csv(mock)
    assert res["valid"] is False
    assert "empty" in res["error"].lower()


def test_validate_csv_no_rows():
    mock = MockUploadedCSV("header_only.csv", "Advertisement_Text,Risk_Label\n")
    res = validate_csv(mock)
    assert res["valid"] is False
    assert "no data rows" in res["error"].lower()


def test_run_batch_analysis_functional():
    df = pd.DataFrame({
        "ad_content": [
            "Bank accounts for sale, no KYC required! Guaranteed instant access. Call 9876543210. Telegram @seller",
            "Monthly salary credited to employee account Rohan Kumar",
            "Tiny",  # Below MIN_TEXT_LENGTH
        ],
        "label": ["High Risk", "Safe", "Unknown"],
    })

    results = run_batch_analysis(df, text_column="ad_content", label_column="label")

    assert len(results) == 3
    # First row should be flagged High Risk by rule engine
    assert results.iloc[0]["risk_level"] in ("High", "Critical")
    assert results.iloc[0]["validation_status"] == "OK"
    assert results.iloc[0]["tfidf_status"] in ("available", "unavailable")
    assert results.iloc[0]["distilbert_status"] == "skipped"
    assert results.iloc[0]["distilbert_error"] == "Inference skipped for batch performance."
    assert "9876543210" in results.iloc[0]["phone_numbers"] or "@seller" in results.iloc[0]["original_text"]
    assert results.iloc[0]["ground_truth"] == "High Risk"

    # Second row should be Low
    assert results.iloc[1]["risk_level"] == "Low"
    assert results.iloc[1]["ground_truth"] == "Safe"

    # Third row should be marked invalid due to length
    assert "INVALID" in results.iloc[2]["validation_status"]
    assert results.iloc[2]["tfidf_status"] == "not_run"


def test_export_safe_csv_neutralizes_formulas():
    df = pd.DataFrame({
        "text": ["=2+5", "Normal text", "@hyperlink('evil.com')"],
        "score": [100, 0, 50],
    })
    csv_str = export_safe_csv(df)
    # The cell starting with = must have been tab-prepended
    assert "\t=2+5" in csv_str
    assert "\t@hyperlink" in csv_str
