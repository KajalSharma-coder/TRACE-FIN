from src.recommendations import get_case_recommendation


def test_syntax_only_url_recommends_content_review_without_calling_domain_fraudulent():
    recommendation = get_case_recommendation({
        "analysis_mode": "website_url_(syntax_only)_unified",
        "risk_level": "Insufficient evidence",
        "risk_score": None,
        "review_required": True,
        "urls": ["https://unverified-fastloan.biz"],
    })
    assert "cannot establish whether the page is fraudulent" in recommendation
    assert "Inspect URL with live content analysis" in recommendation
    assert "unverified-fastloan.biz" not in recommendation


def test_high_medium_and_low_recommendations_use_existing_evidence():
    high = get_case_recommendation({"risk_level": "High", "risk_score": 80, "review_required": True, "matched_categories": ["KYC evasion"]})
    medium = get_case_recommendation({"risk_level": "Medium", "risk_score": 45, "review_required": True, "urls": ["https://example.test"]})
    low = get_case_recommendation({"risk_level": "Low", "risk_score": 5, "review_required": False})
    assert "matched indicators" in high
    assert "verify the source" in medium
    assert "does not guarantee" in low


def test_unavailable_score_and_models_are_disclosed():
    recommendation = get_case_recommendation({
        "analysis_mode": "direct_text_unified",
        "risk_level": "Insufficient evidence",
        "risk_score": None,
        "review_required": True,
        "ml_prediction": None,
        "hf_prediction": None,
    })
    assert "reliable risk score is unavailable" in recommendation
    assert "low risk" in recommendation


def test_live_url_does_not_repeat_live_fetch_instruction():
    recommendation = get_case_recommendation({
        "analysis_mode": "website_url_unified",
        "risk_level": "Medium",
        "risk_score": 42,
        "review_required": True,
        "urls": ["https://example.test"],
        "matched_categories": ["Urgency"],
    })
    assert "live content" not in recommendation
    assert "detected indicators" in recommendation


def test_missing_recommendation_data_still_produces_safe_guidance():
    recommendation = get_case_recommendation({"review_required": True})
    assert recommendation
    assert "review" in recommendation.lower()
