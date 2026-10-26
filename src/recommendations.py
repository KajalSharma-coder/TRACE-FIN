"""Context-aware investigator recommendations for persisted case dossiers."""

from __future__ import annotations

from collections.abc import Mapping
from numbers import Number
from typing import Any


def _has_score(record: Mapping[str, Any]) -> bool:
    score = record.get("risk_score", record.get("final_score"))
    return isinstance(score, Number) and not isinstance(score, bool)


def _indicators_present(record: Mapping[str, Any]) -> bool:
    return any(record.get(key) for key in (
        "matched_categories", "urls", "emails", "phone_numbers", "payment_identifiers", "evidence",
    ))


def _is_syntax_only_url(record: Mapping[str, Any]) -> bool:
    mode = str(record.get("analysis_mode") or "").casefold()
    return "syntax_only" in mode or "syntax only" in mode


def _is_url_analysis(record: Mapping[str, Any]) -> bool:
    mode = str(record.get("analysis_mode") or "").casefold()
    return "url" in mode or "website" in mode


def _model_outputs_unavailable(record: Mapping[str, Any]) -> bool:
    return record.get("ml_prediction") is None and record.get("hf_prediction") is None


def get_case_recommendation(record: Mapping[str, Any]) -> str:
    """Return a concise, evidence-aware recommendation without changing risk scoring."""
    risk = str(record.get("risk_level") or record.get("final_verdict") or "").casefold()
    has_score = _has_score(record)
    indicators = _indicators_present(record)
    review_required = bool(record.get("review_required"))

    if _is_syntax_only_url(record):
        return (
            "URL and domain checks alone cannot establish whether the page is fraudulent. "
            "Use Inspect URL with live content analysis, or manually review the page content."
        )

    if not has_score or "insufficient" in risk or "unscored" in risk:
        if _is_url_analysis(record):
            return (
                "A reliable risk score is unavailable because page content was not available to the analysis. "
                "Review the page content manually or retry the existing URL inspection workflow if content retrieval failed."
            )
        return (
            "A reliable risk score is unavailable because the available analysis evidence was incomplete. "
            "Review the source content manually and do not treat this case as low risk."
        )

    if "critical" in risk or "high" in risk:
        recommendation = (
            "Review the matched indicators and preserve the relevant case material before taking action."
            if indicators else
            "Review the available case material and preserve the case record before taking action."
        )
    elif "medium" in risk:
        recommendation = (
            "Review the detected indicators and verify the source before making a decision."
            if indicators else
            "Review the available case material and verify the source before making a decision."
        )
    elif "low" in risk:
        recommendation = (
            "Available checks did not detect strong risk signals. This does not guarantee that the source is safe; "
            "continue with proportionate verification."
        )
    else:
        recommendation = "Review the available case material and verify the source before making a decision."

    if review_required and _model_outputs_unavailable(record):
        recommendation += " Statistical model outputs were unavailable, so this recommendation relies on the available rule indicators."
    return recommendation
