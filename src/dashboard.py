"""Small pure helpers for building dashboard values from persisted records."""

from collections import Counter


def build_dashboard_snapshot(records: list[dict]) -> dict:
    """Summarize investigator-created records; keep synthetic fixtures separate."""
    real_records = [r for r in records if not r.get("is_synthetic")]
    demo_records = [r for r in records if r.get("is_synthetic")]
    risks = Counter((r.get("risk_level") or "Low").capitalize() for r in real_records)
    statuses = Counter(r.get("investigation_status") or "Open" for r in real_records)
    activity = Counter((r.get("submitted_at") or "")[:10] for r in real_records)
    categories = Counter(
        category for record in real_records
        for category in (record.get("matched_categories") or [])
    )
    ordered = sorted(real_records, key=lambda r: r.get("submitted_at") or "", reverse=True)
    return {
        "total": len(real_records),
        "risk_counts": {key: risks.get(key, 0) for key in ("Critical", "High", "Medium", "Low")},
        "status_counts": dict(statuses),
        "activity": [{"date": day, "count": count} for day, count in sorted(activity.items())],
        "category_counts": dict(categories),
        "recent": ordered[:10],
        "demo_count": len(demo_records),
    }


def load_dashboard_snapshot(record_loader) -> tuple[dict, str | None]:
    """Return an empty but well-shaped dashboard when storage cannot be read."""
    try:
        return build_dashboard_snapshot(record_loader()), None
    except Exception:
        return build_dashboard_snapshot([]), (
            "The analysis database is unavailable. Dashboard values are empty until it can be reached."
        )
