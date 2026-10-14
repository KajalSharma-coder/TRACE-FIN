"""
TRACE//FIN — Synthetic Demo Data
Varied sample advertisements seeded once when the database is empty.

All text is fictional. Domains use example.com.
Real account credentials, payment secrets, or personal data are never included.
"""

from datetime import datetime, timezone, timedelta

from src.database import insert_record, record_count, generate_record_id
from src.demo_analyzer import analyze_ad


# ── Sample Advertisements ──────────────────────────────────────────────

_SAMPLES = [
    {
        "ad_text": (
            "🔥 BANK ACCOUNTS FOR SALE 🔥\n"
            "Current accounts and savings accounts available. No KYC required!\n"
            "Guaranteed instant access. DM me on Telegram @findeals_example.\n"
            "Limited time offer — only 5 left. Pay in advance via UPI.\n"
            "Contact: +91-98765-43210\n"
            "Visit: http://fastaccounts.example.com/buy"
        ),
        "description": "Hypothetical bank account offered for sale",
    },
    {
        "ad_text": (
            "💳 ATM & Debit Cards Available 💳\n"
            "Buy pre-activated debit cards and ATM cards.\n"
            "No verification, no questions asked. 100% guaranteed approval.\n"
            "Crypto payments accepted (BTC/USDT).\n"
            "WhatsApp: +91-87654-32109\n"
            "UPI: cardseller@exampleupi\n"
            "Hurry — act now before stock runs out!"
        ),
        "description": "Hypothetical card advertisement with suspicious conditions",
    },
    {
        "ad_text": (
            "Open a Zero-Balance Savings Account with XYZ Bank\n\n"
            "Enjoy 7% interest p.a. on your savings. Full KYC required as per RBI guidelines.\n"
            "Visit your nearest branch or apply online at https://www.xyzbank.example.com/savings.\n"
            "Documents required: Aadhaar, PAN, and address proof.\n"
            "Terms and conditions apply. DICGC insured up to ₹5,00,000."
        ),
        "description": "Generic legitimate savings-account advertisement",
    },
    {
        "ad_text": (
            "⚠️ Protect Your Financial Identity ⚠️\n\n"
            "Never share your ATM PIN, CVV, or OTP with anyone.\n"
            "Banks will never ask for your password over phone or email.\n"
            "Report suspicious activity to your bank immediately.\n"
            "Learn more: https://cybersafe.example.com/awareness\n\n"
            "— National Cyber Safety Initiative (Fictional)"
        ),
        "description": "Financial-awareness advertisement",
    },
    {
        "ad_text": (
            "Freelancer? Need a current account with easy access?\n"
            "Quick setup with minimal paperwork. Competitive transaction fees.\n"
            "Contact our team: freelancers@bizbank.example.com\n"
            "Call: +91-11-2345-6789\n\n"
            "Note: Standard verification process applies."
        ),
        "description": "Ambiguous advertisement requiring review",
    },
]


def seed_demo_data() -> int:
    """
    Insert synthetic sample records if the database is empty.
    Returns the number of records seeded (0 if data already exists).
    """
    if record_count() > 0:
        return 0

    seeded = 0
    base_time = datetime.now(timezone.utc) - timedelta(days=4)

    for i, sample in enumerate(_SAMPLES):
        # Analyze with the demo analyzer
        result = analyze_ad(sample["ad_text"])

        record = {
            "record_id": generate_record_id(),
            "ad_text": sample["ad_text"],
            "submitted_at": (base_time + timedelta(days=i, hours=i * 3)).isoformat(),
            "analysis_mode": "demo",
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
            "matched_categories": result["matched_categories"],
            "evidence": result["evidence"],
            "urls": result["urls"],
            "phone_numbers": result["phone_numbers"],
            "payment_identifiers": result["payment_identifiers"],
            "review_required": result["review_required"],
            "review_recommendation": result.get("review_recommendation", "Review required"),
            "investigation_status": "Open",
            "is_synthetic": True,
        }

        insert_record(record)
        seeded += 1

    return seeded
