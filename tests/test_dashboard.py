from src.dashboard import build_dashboard_snapshot, load_dashboard_snapshot


def test_empty_dashboard_has_zero_counts_and_no_records():
    snapshot = build_dashboard_snapshot([])
    assert snapshot["total"] == 0
    assert snapshot["risk_counts"] == {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    assert snapshot["recent"] == []
    assert snapshot["demo_count"] == 0


def test_dashboard_excludes_synthetic_examples_from_investigator_metrics():
    records = [
        {"record_id": "demo", "is_synthetic": True, "risk_level": "Critical"},
        {"record_id": "saved", "is_synthetic": False, "risk_level": "High",
         "submitted_at": "2026-01-02T10:00:00", "matched_categories": ["KYC bypass"]},
    ]
    snapshot = build_dashboard_snapshot(records)
    assert snapshot["total"] == 1
    assert snapshot["risk_counts"]["High"] == 1
    assert snapshot["risk_counts"]["Critical"] == 0
    assert snapshot["category_counts"] == {"KYC bypass": 1}
    assert [row["record_id"] for row in snapshot["recent"]] == ["saved"]
    assert snapshot["demo_count"] == 1


def test_missing_database_returns_graceful_empty_dashboard():
    def unavailable_store():
        raise OSError("private database details must not leak")

    snapshot, error = load_dashboard_snapshot(unavailable_store)
    assert snapshot["total"] == 0
    assert snapshot["recent"] == []
    assert "database is unavailable" in error
    assert "private database details" not in error
