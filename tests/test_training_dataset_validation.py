import pandas as pd

from scripts.validate_training_dataset import audit_dataset, detect_pii, _is_true


def _row(index, text, label="Safe", **overrides):
    row = {
        "Candidate_ID": f"cand-{index}",
        "Advertisement_Text": text,
        "Risk_Label": label,
        "Content_Subtype": "financial-awareness",
        "Source_Provenance": f"source-{index}",
        "Campaign_or_Template_Group": f"group-{index}",
        "Collection_Date": "2026-10-24",
        "Evidence": "Reviewed evidence span",
        "Review_Status": "Reviewed",
        "Is_Synthetic": "False",
        "Assigned_Split": "",
    }
    row.update(overrides)
    return row


def test_pii_detection_reports_categories_without_exposing_values():
    findings = detect_pii("Contact +91 9876543210, email a.person@example.com, IFSC ICIC0123456")
    assert {"email", "phone_or_long_number", "ifsc"} <= set(findings)


def test_boolean_parser_handles_blank_missing_whitespace_true_false_and_invalid_values():
    assert _is_true(True) is True
    assert _is_true(" true ") is True
    assert _is_true("synthetic") is True
    assert _is_true("false") is False
    assert _is_true("  ") is False
    assert _is_true("") is False
    assert _is_true(None) is False
    assert _is_true("not-a-boolean") is False


def test_boolean_audit_counts_true_values_and_warns_on_invalid_values(tmp_path):
    missing_value = _row(2, "Missing synthetic flag")
    missing_value.pop("Is_Synthetic")
    rows = [
        _row(1, "Explicit synthetic", Is_Synthetic=" true "),
        _row(2, "Explicit real", Is_Synthetic="false"),
        _row(3, "Blank synthetic", Is_Synthetic=""),
        _row(4, "Whitespace synthetic", Is_Synthetic="   "),
        missing_value,
        _row(6, "Invalid synthetic flag", Is_Synthetic="sometimes"),
    ]
    path = tmp_path / "boolean-values.csv"
    pd.DataFrame(rows).to_csv(path, index=False)
    result = audit_dataset(path)
    assert result["synthetic_rows"] == 1
    assert result["invalid_synthetic_values"] == ["sometimes"]
    assert any("Invalid Is_Synthetic" in warning for warning in result["warnings"])


def test_duplicates_and_conflicting_labels_are_reported(tmp_path):
    rows = [
        _row(1, "Legitimate savings awareness notice", Campaign_or_Template_Group="same"),
        _row(2, "Legitimate savings awareness notice", Campaign_or_Template_Group="same", Risk_Label="High Risk"),
        _row(3, "Legitimate savings awareness notice with a small change", Campaign_or_Template_Group="other"),
    ]
    path = tmp_path / "candidates.csv"
    pd.DataFrame(rows).to_csv(path, index=False)
    result = audit_dataset(path)
    assert result["exact_duplicate_rows"] == 2
    assert result["normalized_duplicate_rows"] >= 2
    assert result["conflicting_groups"]
    assert result["ready"] is False


def test_synthetic_and_unreviewed_rows_are_excluded(tmp_path):
    rows = [
        _row(1, "Synthetic safe fixture", Is_Synthetic="True"),
        _row(2, "Needs review financial message", Review_Status="Needs Review"),
    ]
    path = tmp_path / "candidates.csv"
    pd.DataFrame(rows).to_csv(path, index=False)
    result = audit_dataset(path)
    assert result["eligible_rows"] == 0
    assert result["synthetic_rows"] == 1
    assert any("Synthetic" in warning for warning in result["warnings"])
    assert result["ready"] is False


def test_insufficient_template_diversity_is_not_ready(tmp_path):
    rows = [_row(i, f"Distinct reviewed financial notice {i}") for i in range(10)]
    path = tmp_path / "candidates.csv"
    pd.DataFrame(rows).to_csv(path, index=False)
    result = audit_dataset(path)
    assert result["eligible_template_counts"]["Safe"] == 10
    assert result["split"]["grouped_readiness"] is False
    assert result["ready"] is False


def test_source_campaign_and_template_split_leakage_is_reported(tmp_path):
    rows = [
        _row(1, "Safe message one", Source_Provenance="same-source", Campaign_or_Template_Group="same-group", Assigned_Split="train"),
        _row(2, "Safe message two", Source_Provenance="same-source", Campaign_or_Template_Group="same-group", Assigned_Split="test"),
    ]
    path = tmp_path / "candidates.csv"
    pd.DataFrame(rows).to_csv(path, index=False)
    result = audit_dataset(path)
    assert result["split"]["assessed"] is True
    assert result["split"]["leakage"]["_group"]
    assert result["split"]["leakage"]["Source_Provenance"]
    assert result["ready"] is False
