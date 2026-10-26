"""
TRACE//FIN — Phase 2 Detector Test Suite
Comprehensive unit, regression, integration, and database migration test suite.
"""

import os
import sys
import pytest

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import RISK_LEVELS, STANDARDIZED_RISK_TIERS
from src.detector import (
    analyze_ad,
    _score_to_risk_level,
    CAT_ACCOUNT_CARD_SALE,
    CAT_KYC_EVASION,
    CAT_ACCOUNT_RENTAL,
    CAT_SUSPICIOUS_SOLICITATION,
    CAT_URGENCY_SECRECY,
    LEVEL_LOW,
    LEVEL_MEDIUM,
    LEVEL_HIGH,
    LEVEL_CRITICAL,
)
from src.database import (
    init_db,
    insert_record,
    get_record,
    get_all_records,
    search_records,
    get_dashboard_metrics,
    record_count,
    update_status,
)


# ── 1. Empty Input ─────────────────────────────────────────────────────

def test_empty_input():
    res = analyze_ad("")
    assert res["risk_score"] == 0
    assert res["risk_level"] == LEVEL_LOW
    assert res["matched_categories"] == []
    assert res["evidence"] == []
    assert res["review_required"] is False
    assert "disclaimer" in res


# ── 2. Whitespace-Only Input ──────────────────────────────────────────

def test_whitespace_only_input():
    res = analyze_ad("   \n\t  \r  ")
    assert res["risk_score"] == 0
    assert res["risk_level"] == LEVEL_LOW
    assert res["matched_categories"] == []
    assert res["evidence"] == []
    assert res["review_required"] is False


# ── 3. Ordinary Legitimate Bank Advertisement ──────────────────────────

def test_legitimate_bank_advertisement():
    text = (
        "Open a Zero-Balance Savings Account with XYZ Bank. "
        "Enjoy 6.5% interest p.a. on deposits. Full KYC required as per RBI guidelines. "
        "Visit your nearest branch or apply online at https://www.xyzbank.example.com. "
        "DICGC insured up to ₹5,00,000."
    )
    res = analyze_ad(text)
    assert res["risk_level"] == LEVEL_LOW
    assert res["risk_score"] < 25
    assert res["review_required"] is False


# ── 4. Educational KYC Explanation ────────────────────────────────────

def test_educational_kyc_explanation():
    text = (
        "Educational Guide on Central Banking KYC Requirements: "
        "Why is KYC mandatory? Know Your Customer helps financial institutions prevent fraud. "
        "Banks will never ask for your password or OTP over the phone. "
        "Read full consumer advisory at https://cybersafety.example.com/kyc-facts."
    )
    res = analyze_ad(text)
    assert res["risk_level"] == LEVEL_LOW
    assert res["risk_score"] < 25
    # Should detect educational mitigation evidence
    assert any("Mitigation" in ev or "educational" in ev.lower() or "advisory" in ev.lower() for ev in res["evidence"])


# ── 5. Normal Payment Reminder ─────────────────────────────────────────

def test_normal_payment_reminder():
    text = (
        "Payment Reminder: Your electricity bill payment of $65 is due on May 20. "
        "Please pay on our portal https://power.example.com or via UPI to bills@okaxis. "
        "For support, contact billing@power.example.com or call 1800-234-5678."
    )
    res = analyze_ad(text)
    assert res["risk_level"] == LEVEL_LOW
    assert res["risk_score"] < 25
    assert "https://power.example.com" in res["urls"]
    assert "billing@power.example.com" in res["emails"]
    assert "bills@okaxis" in res["payment_identifiers"]


# ── 6. Suspicious Bank-Account Sale ────────────────────────────────────

def test_suspicious_bank_account_sale():
    text = (
        "Bank account available for sale! Current accounts with netbanking and full kits ready. "
        "Fast delivery. DM on Telegram for rates."
    )
    res = analyze_ad(text)
    assert CAT_ACCOUNT_CARD_SALE in res["matched_categories"]
    assert res["risk_score"] >= 25
    assert res["risk_level"] in (LEVEL_MEDIUM, LEVEL_HIGH, LEVEL_CRITICAL)
    assert res["review_required"] is True
    assert len(res["evidence"]) > 0


# ── 7. Account Offer Combined with KYC Bypass ─────────────────────────

def test_account_offer_combined_with_kyc_bypass():
    text = (
        "🔥 BANK ACCOUNTS FOR SALE 🔥 "
        "Current accounts and savings accounts available. No KYC required! "
        "Guaranteed instant access. Pay in advance via UPI to seller@okaxis. "
        "Contact: +91-98765-43210 or Telegram @dealmaker"
    )
    res = analyze_ad(text)
    assert CAT_ACCOUNT_CARD_SALE in res["matched_categories"]
    assert CAT_KYC_EVASION in res["matched_categories"]
    # Compounding risk should push this into Critical
    assert res["risk_score"] >= 75
    assert res["risk_level"] == LEVEL_CRITICAL
    assert res["review_required"] is True
    assert any("Compounding Risk" in ev for ev in res["evidence"])


# ── 8. Account Rental or Receiving Funds for Commission ────────────────

def test_account_rental_or_mule_recruitment():
    text = (
        "Looking for people to rent your bank account and earn commission. "
        "Receive payments for us and keep 10% commission on each transfer. "
        "Daily payouts guaranteed. Contact dispatch@funds.example.com."
    )
    res = analyze_ad(text)
    assert CAT_ACCOUNT_RENTAL in res["matched_categories"]
    assert res["risk_score"] >= 35
    assert res["risk_level"] in (LEVEL_MEDIUM, LEVEL_HIGH, LEVEL_CRITICAL)
    assert res["review_required"] is True


# ── 9. Suspicious Urgency and Secrecy Combinations ─────────────────────

def test_suspicious_urgency_and_secrecy():
    text = (
        "Need someone to use your account for transfers. "
        "Keep 15% commission. Don't tell your bank, keep this secret! "
        "Only 2 slots left, urgent deal, act fast!"
    )
    res = analyze_ad(text)
    assert CAT_ACCOUNT_RENTAL in res["matched_categories"]
    assert CAT_URGENCY_SECRECY in res["matched_categories"]
    assert res["risk_score"] >= 50
    assert res["risk_level"] in (LEVEL_HIGH, LEVEL_CRITICAL)


# ── 10. URL Extraction ────────────────────────────────────────────────

def test_url_extraction():
    text = (
        "Visit our portal at https://secure.example.com/login and http://test.example.org/buy. "
        "Also check www.example.net/info."
    )
    res = analyze_ad(text)
    assert "https://secure.example.com/login" in res["urls"]
    assert "http://test.example.org/buy" in res["urls"]
    assert any("www.example.net" in u for u in res["urls"])


# ── 11. Email Extraction ──────────────────────────────────────────────

def test_email_extraction():
    text = "Send queries to admin@example.com or sales.desk@company.example.org."
    res = analyze_ad(text)
    assert "admin@example.com" in res["emails"]
    assert "sales.desk@company.example.org" in res["emails"]


# ── 12. Phone-Like Number Extraction ──────────────────────────────────

def test_phone_number_extraction():
    text = "Call support at +91-98765-43210 or office at (022) 2456-7890."
    res = analyze_ad(text)
    assert len(res["phone_numbers"]) >= 1
    assert any("98765" in p for p in res["phone_numbers"])


# ── 13. UPI-Style Identifier Extraction ───────────────────────────────

def test_upi_identifier_extraction():
    text = "Pay via UPI to merchant@okaxis or user@upi or seller@paytm."
    res = analyze_ad(text)
    assert "merchant@okaxis" in res["payment_identifiers"]
    assert "user@upi" in res["payment_identifiers"]
    assert "seller@paytm" in res["payment_identifiers"]


# ── 14. Score Stays Within 0–100 ──────────────────────────────────────

def test_score_bounded_0_to_100():
    # Extreme ad triggering every rule multiple times
    hyper_ad = (
        "🔥 BANK ACCOUNTS FOR SALE 🔥 Buy verified bank accounts, debit cards in bulk! "
        "No KYC, skip verification, no ID needed! Full kit accounts with SIM and netbanking. "
        "Rent your bank account and receive payments for commission! "
        "Share your OTP and PIN. Pay upfront advance fee in crypto BTC/USDT. "
        "Don't tell your bank, keep confidential! Only 2 accounts left, hurry! "
        "Contact: +91-98765-43210, user@okaxis, https://shady.example.com"
    )
    res = analyze_ad(hyper_ad)
    assert 0 <= res["risk_score"] <= 100
    assert res["risk_score"] == 100
    assert res["risk_level"] == LEVEL_CRITICAL

    # Clean text
    clean_ad = "Happy financial literacy week from your neighborhood community bank!"
    res_clean = analyze_ad(clean_ad)
    assert 0 <= res_clean["risk_score"] <= 100


# ── 15. Correct Risk-Level Mapping at Score Boundaries ────────────────

def test_risk_level_score_boundaries():
    assert _score_to_risk_level(0) == LEVEL_LOW
    assert _score_to_risk_level(24) == LEVEL_LOW
    assert _score_to_risk_level(25) == LEVEL_MEDIUM
    assert _score_to_risk_level(49) == LEVEL_MEDIUM
    assert _score_to_risk_level(50) == LEVEL_HIGH
    assert _score_to_risk_level(74) == LEVEL_HIGH
    assert _score_to_risk_level(75) == LEVEL_CRITICAL
    assert _score_to_risk_level(100) == LEVEL_CRITICAL


# ── 16. Evidence is Present When Rules Match ──────────────────────────

def test_evidence_presence_on_match():
    text = "Buy verified bank accounts with instant access."
    res = analyze_ad(text)
    assert len(res["matched_categories"]) > 0
    assert len(res["evidence"]) > 0
    for ev in res["evidence"]:
        assert isinstance(ev, str)
        assert len(ev) > 5


def test_ocr_recruitment_ad_matches_actual_financial_threat_indicators():
    text = (
        "Guaranteed earnings of ₹10,000–₹25,000 per month. Use your personal bank account to receive "
        "and forward payments. Send bank account number, IFSC, OTP, and KYC documents. "
        "Pay ₹1,499 activation bonus/fee. Limited seats - avoid contacting the bank."
    )
    result = analyze_ad(text)

    assert result["risk_score"] > 0
    assert CAT_ACCOUNT_RENTAL in result["matched_categories"]
    assert CAT_SUSPICIOUS_SOLICITATION in result["matched_categories"]
    assert CAT_URGENCY_SECRECY in result["matched_categories"]
    assert any("personal bank account" in item.lower() for item in result["evidence"])
    assert any("otp" in item.lower() for item in result["evidence"])
    assert any("activation" in item.lower() for item in result["evidence"])
    assert any("guaranteed earnings" in item.lower() for item in result["evidence"])
    assert len(result["evidence"]) == len(set(result["evidence"]))


def test_ocr_spacing_and_punctuation_variants_are_normalized():
    text = (
        "GUARANTEED EARNINGS OF Rs. 10,000 - 25,000 PER MONTH\n"
        "Use   your   personal   bank   account to receive and forward payments.\n"
        "Requests for bank account number, IFSC, OTP and KYC documents.\n"
        "Pay 1499 activation bonus/fee; limited seats; avoid contacting the bank."
    )
    result = analyze_ad(text)

    assert result["risk_score"] > 0
    assert result["matched_categories"]
    assert any("receive or forward" in item.lower() for item in result["evidence"])


def test_legitimate_security_notice_does_not_trigger_credential_solicitation():
    text = (
        "Bank security notice: Your OTP is 123456 and valid for 10 minutes. "
        "Never share your OTP, PIN, password, account number, or KYC documents. "
        "Contact the bank through the official branch or app if you did not request it."
    )
    result = analyze_ad(text)

    assert result["risk_score"] < 25
    assert result["review_required"] is False


def test_legitimate_financial_awareness_notice_does_not_trigger_account_rental():
    text = (
        "Financial awareness notice: Never rent or lend your personal bank account. "
        "Money mule recruitment can cause account closure. Banks will never ask for OTPs. "
        "Report suspicious transfer requests to the official bank."
    )
    result = analyze_ad(text)

    assert result["risk_score"] < 25


# ── 17. Same Input Returns the Same Result (Deterministic) ────────────

def test_deterministic_output():
    text = "Debit cards available in bulk. No verification needed. Contact sales@cards.example.com."
    res1 = analyze_ad(text)
    res2 = analyze_ad(text)
    assert res1["risk_score"] == res2["risk_score"]
    assert res1["risk_level"] == res2["risk_level"]
    assert res1["matched_categories"] == res2["matched_categories"]
    assert res1["evidence"] == res2["evidence"]
    assert res1["urls"] == res2["urls"]
    assert res1["emails"] == res2["emails"]
    assert res1["phone_numbers"] == res2["phone_numbers"]
    assert res1["payment_identifiers"] == res2["payment_identifiers"]


# ── 18. Ordinary Contact Details Alone Do Not Cause High Risk ─────────

def test_contact_details_alone_not_suspicious():
    text = (
        "Customer Service Desk:\n"
        "Email: support@example.com\n"
        "Phone: +1 (555) 019-2834\n"
        "Website: https://www.example.com\n"
        "Payment support: contact@okaxis"
    )
    res = analyze_ad(text)
    assert res["risk_score"] == 0
    assert res["risk_level"] == LEVEL_LOW
    assert res["review_required"] is False
    assert len(res["emails"]) > 0
    assert len(res["urls"]) > 0
    assert len(res["phone_numbers"]) > 0


# ── 19. Existing Database Records Remain Readable & Backward Compatible ─

def test_database_records_readable_and_backward_compatible():
    # Initialize DB (executes safe migrations)
    init_db()

    # Insert a Phase 2 record with emails
    test_record = {
        "ad_text": "Bank account available for sale. Email dealer@example.com",
        "analysis_mode": "rule_based",
        "risk_score": 60,
        "risk_level": "High",
        "matched_categories": [CAT_ACCOUNT_CARD_SALE],
        "evidence": ["[Financial Account or Card Sale] Found account sale offer"],
        "urls": [],
        "emails": ["dealer@example.com"],
        "phone_numbers": [],
        "payment_identifiers": [],
        "review_required": True,
        "review_recommendation": "Investigator review required",
        "investigation_status": "Open",
        "is_synthetic": True,
    }
    rec_id = insert_record(test_record)
    assert rec_id.startswith("TF-")

    # Read back
    fetched = get_record(rec_id)
    assert fetched is not None
    assert fetched["record_id"] == rec_id
    assert fetched["risk_level"] == "High"
    assert "dealer@example.com" in fetched["emails"]
    assert isinstance(fetched["evidence"], list)

    # Status update
    ok = update_status(rec_id, "Reviewing")
    assert ok is True
    updated = get_record(rec_id)
    assert updated["investigation_status"] == "Reviewing"

    # Search
    search_res = search_records(query=rec_id)
    assert len(search_res) == 1
    assert search_res[0]["record_id"] == rec_id

    # Filter by standardized risk level
    filt_res = search_records(risk_level="High")
    assert any(r["record_id"] == rec_id for r in filt_res)

    # Metrics
    metrics = get_dashboard_metrics()
    assert "Critical" in metrics["risk_counts"]
    assert "High" in metrics["risk_counts"]
    assert "Medium" in metrics["risk_counts"]
    assert "Low" in metrics["risk_counts"]
    assert metrics["risk_counts"]["High"] >= 1


# ── 20. Existing Pages Can Import and Call Analyzer Successfully ───────

def test_pages_import_and_call_analyzer():
    import app
    assert hasattr(app, "st")

    from src.detector import analyze_ad as detector_analyze
    test_run = detector_analyze("Test advertisement")
    assert isinstance(test_run, dict)
    assert "risk_score" in test_run
    assert "risk_level" in test_run
    assert test_run["risk_level"] in STANDARDIZED_RISK_TIERS
