"""
TRACE//FIN — Risk Synthesis and Rule Engine Regression Tests
Covers:
- Suspicious text across major financial ad fraud archetypes
- Legitimate benign text (advisories, corporate payroll, donations)
- Repeated indicators and score bound enforcement [0, 100]
- Empty and whitespace input handling
- Matched rules and evidence reporting
- Engine consensus and divergence resolution (compute_unified_verdict)
- Internal consistency between verdict, score, status, and recommendation
"""

import pytest
from src.detector import analyze_ad, compute_unified_verdict


# ── 1. Suspicious Financial Advertisement Tests ─────────────────────────

def test_suspicious_account_sale_hdfc():
    """Verify detection of specific bank account sale patterns with KYC."""
    text = "Selling fully KYC verified HDFC account with debit card and internet banking access. DM @bankbroker"
    res = analyze_ad(text)
    assert res["risk_score"] >= 50
    assert res["risk_level"] in ("High", "Critical")
    assert "Financial Account or Card Sale" in res["matched_categories"]
    assert "KYC Evasion & Verification Bypass" in res["matched_categories"]
    assert len(res["matched_rules"]) >= 2
    rule_names = [r["rule_name"] for r in res["matched_rules"]]
    assert any("Bank Account Sale" in name or "KYC" in name for name in rule_names)


def test_suspicious_account_rental_cashout():
    """Verify detection of account rental and instant cashout services."""
    text = "Need current account for instant cashout service. Daily 10% commission. Contact 9876543210"
    res = analyze_ad(text)
    assert res["risk_score"] >= 35
    assert "Account Rental & Mule Recruitment" in res["matched_categories"]
    assert len(res["phone_numbers"]) > 0


def test_suspicious_hawala_solicitation():
    """Verify detection of informal value transfer (hawala) solicitations."""
    text = "Need current account for hawala transactions. High daily limit required, urgent payout."
    res = analyze_ad(text)
    assert res["risk_score"] >= 40
    assert "Suspicious Financial Solicitation" in res["matched_categories"]


def test_suspicious_kyc_bypass():
    """Verify detection of KYC circumvention and mule accounts."""
    text = "Pre-verified bank accounts available without KYC documentation. Ready to use."
    res = analyze_ad(text)
    assert res["risk_score"] >= 30
    assert "KYC Evasion & Verification Bypass" in res["matched_categories"]


# ── 2. Legitimate and Benign Advertisement Tests ────────────────────────

def test_legitimate_bank_advisory():
    """Verify that official bank security advisories are mitigated to safe scores."""
    text = (
        "Advisory from State Bank: Never share your OTP, UPI PIN, or bank account password with anyone. "
        "Report cyber fraud immediately at cybercrime.gov.in."
    )
    res = analyze_ad(text)
    assert res["risk_score"] <= 24
    assert res["risk_level"] == "Low"
    assert res["review_required"] is False


def test_legitimate_donation_appeal():
    """Verify that legitimate charitable donation appeals receive low risk scores."""
    text = (
        "Support flood relief operations. Send donations to our official NGO account. "
        "Receipts will be provided for 80G tax exemption. Visit https://relief-ngo.org"
    )
    res = analyze_ad(text)
    assert res["risk_score"] <= 24
    assert res["risk_level"] == "Low"
    assert res["review_required"] is False


def test_legitimate_salary_credit():
    """Verify that standard corporate salary / HR notifications are not flagged."""
    text = "Monthly salary has been credited to your corporate salary account. Check your payslip on the portal."
    res = analyze_ad(text)
    assert res["risk_score"] <= 24
    assert res["risk_level"] == "Low"
    assert "Account & Payment Instrument Sale" not in res["matched_categories"]


# ── 3. Repeated Indicators and Score Bounds ─────────────────────────────

def test_repeated_indicators_bounded():
    """Verify that repeating indicators does not inflate the score beyond 100."""
    text = (
        "Selling bank account selling bank account selling bank account! "
        "KYC verified KYC verified KYC verified! Instant cashout instant cashout! "
        "Urgent urgent contact now! Call 9876543210 @seller https://bank.com"
    )
    res = analyze_ad(text)
    assert 0 <= res["risk_score"] <= 100
    assert res["risk_score"] >= 50


def test_empty_and_whitespace_input():
    """Verify that empty or whitespace-only input returns zero score and safe status."""
    res_empty = analyze_ad("")
    assert res_empty["risk_score"] == 0
    assert res_empty["risk_level"] == "Low"
    assert res_empty["matched_categories"] == []
    assert res_empty["matched_rules"] == []
    assert res_empty["review_required"] is False
    assert res_empty["evidence"] == []

    res_spaces = analyze_ad("   \n\t   ")
    assert res_spaces["risk_score"] == 0
    assert res_spaces["risk_level"] == "Low"
    assert res_spaces["matched_categories"] == []
    assert res_spaces["evidence"] == []


# ── 4. Matched Rules Reporting ──────────────────────────────────────────

def test_matched_rules_reporting_when_present():
    """Verify that matched_rules provides structured evidence for investigators."""
    text = "Selling verified netbanking account with pre-KYC access."
    res = analyze_ad(text)
    assert len(res["matched_rules"]) > 0
    for rule in res["matched_rules"]:
        assert "rule_name" in rule
        assert "category" in rule
        assert "evidence" in rule
        assert "weight" in rule
        assert isinstance(rule["weight"], (int, float))


def test_no_rules_matched_reporting():
    """Verify clear reporting when no configured rules match."""
    text = "Meeting scheduled for tomorrow at 10 AM to discuss Q3 marketing strategies."
    res = analyze_ad(text)
    assert res["matched_rules"] == []
    assert res["matched_categories"] == []
    assert "No configured rules matched." in res["evidence"]


# ── 5. Unified Verdict Synthesis (compute_unified_verdict) ─────────────

def test_unified_verdict_consensus_threat():
    """Consensus threat: Rule engine high risk + ML models high risk."""
    rule_res = {
        "risk_score": 75,
        "risk_level": "High",
        "matched_categories": ["Account & Payment Instrument Sale", "KYC Evasion & Verification Bypass"],
        "matched_rules": [{"rule_name": "Account Sale", "evidence": "selling bank account"}],
    }
    ml_res = {"risk_label": "High Risk", "confidence": 0.98}
    hf_res = {"risk_label": "High Risk", "confidence": 0.99}

    verdict = compute_unified_verdict(rule_res, ml_res, hf_res)
    assert verdict["final_verdict"] == "HIGH RISK"
    assert verdict["final_score"] >= 75
    assert verdict["investigation_status"] == "Escalated"
    assert verdict["review_required"] is True
    assert "Priority Action" in verdict["recommendation"]
    assert "Consensus Threat" in verdict["consensus_status"]


def test_unified_verdict_model_alert_without_rules():
    """Model divergence: ML models flag High Risk, but rule score is 0.
    Must route conservatively to MEDIUM RISK and Manual Review, NOT Routine."""
    rule_res = {
        "risk_score": 0,
        "risk_level": "Low",
        "matched_categories": [],
        "matched_rules": [],
    }
    ml_res = {"risk_label": "High Risk", "confidence": 0.88}
    hf_res = {"risk_label": "High Risk", "confidence": 0.92}

    verdict = compute_unified_verdict(rule_res, ml_res, hf_res)
    assert verdict["final_verdict"] == "MEDIUM RISK"
    assert verdict["final_score"] == 50
    assert verdict["investigation_status"] == "Reviewing"
    assert verdict["review_required"] is True
    assert "Manual Review Required" in verdict["recommendation"]
    assert "Manual review is required" in verdict["explanation"]


def test_unified_verdict_consensus_safe():
    """Consensus safe: Rule engine low + both ML models Safe."""
    rule_res = {
        "risk_score": 0,
        "risk_level": "Low",
        "matched_categories": [],
        "matched_rules": [],
    }
    ml_res = {"risk_label": "Safe", "confidence": 0.95}
    hf_res = {"risk_label": "Safe", "confidence": 0.97}

    verdict = compute_unified_verdict(rule_res, ml_res, hf_res)
    assert verdict["final_verdict"] == "LOW RISK"
    assert verdict["final_score"] <= 24
    assert verdict["investigation_status"] == "Closed"
    assert verdict["review_required"] is False
    assert "Routine" in verdict["recommendation"]


def test_unified_verdict_rule_threat_ml_safe():
    """Rule engine detects direct violation, but ML predicted Safe."""
    rule_res = {
        "risk_score": 65,
        "risk_level": "High",
        "matched_categories": ["Account & Payment Instrument Sale"],
        "matched_rules": [{"rule_name": "Account Sale", "evidence": "selling bank account"}],
    }
    ml_res = {"risk_label": "Safe", "confidence": 0.60}
    hf_res = {"risk_label": "Safe", "confidence": 0.55}

    verdict = compute_unified_verdict(rule_res, ml_res, hf_res)
    assert verdict["final_verdict"] == "HIGH RISK"
    assert verdict["investigation_status"] == "Open"
    assert verdict["review_required"] is True
    assert "Priority Review" in verdict["recommendation"]


def test_verdict_consistency_guarantee():
    """Ensure that verdict, score, status, and recommendation never contradict."""
    test_cases = [
        # (rule_score, ml_label, hf_label)
        (80, "High Risk", "High Risk"),
        (0, "High Risk", "High Risk"),
        (0, "Safe", "Safe"),
        (40, "Safe", "High Risk"),
        (15, "High Risk", "Safe"),
    ]

    for r_score, ml_l, hf_l in test_cases:
        r_level = "High" if r_score >= 50 else ("Medium" if r_score >= 25 else "Low")
        r_dict = {"risk_score": r_score, "risk_level": r_level, "matched_categories": []}
        m_dict = {"risk_label": ml_l, "confidence": 0.85}
        h_dict = {"risk_label": hf_l, "confidence": 0.85}

        v = compute_unified_verdict(r_dict, m_dict, h_dict)

        # Invariant 1: Score bounds
        assert 0 <= v["final_score"] <= 100

        # Invariant 2: HIGH RISK must never be marked "Routine" or "Closed"
        if v["final_verdict"] == "HIGH RISK":
            assert v["investigation_status"] in ("Escalated", "Open")
            assert "Routine" not in v["recommendation"]
            assert v["review_required"] is True

        # Invariant 3: LOW RISK must not recommend "Priority" or require review
        if v["final_verdict"] == "LOW RISK":
            assert "Priority" not in v["recommendation"]
            assert v["review_required"] is False
