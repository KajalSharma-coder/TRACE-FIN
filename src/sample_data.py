"""
TRACE//FIN — Synthetic Demo Data
Varied sample advertisements seeded once when the database is empty.

All text is fictional. Domains use example.com.
Real account credentials, payment secrets, or personal data are never included.
"""

from datetime import datetime, timezone, timedelta

from src.database import insert_record, record_count, generate_record_id
from src.detector import analyze_ad


# ── Sample Advertisements ──────────────────────────────────────────────

_SAMPLES = [
    {
        "ad_text": (
            "🔥 BANK ACCOUNTS FOR SALE 🔥\n"
            "Current accounts and savings accounts available. No KYC required!\n"
            "Guaranteed instant access. DM me on Telegram @findeals_example.\n"
            "Limited time offer — only 5 left. Pay in advance via UPI: seller@okaxis\n"
            "Contact: +91-98765-43210 | sales@fastaccounts.example.com\n"
            "Visit: http://fastaccounts.example.com/buy"
        ),
        "description": "Hypothetical bank account offered for sale with KYC bypass",
    },
    {
        "ad_text": (
            "💳 ATM & Debit Cards Available in Bulk 💳\n"
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
            "💼 Earn Daily Passive Income — Rent Your Bank Account 💼\n"
            "Looking for active account holders. Rent your bank account and earn commission.\n"
            "Receive payments for us and keep 10% commission on each transfer.\n"
            "Daily payouts guaranteed. Don't tell your bank.\n"
            "Contact our team on Telegram @muletransfer_example or email dispatch@transfers.example.com"
        ),
        "description": "Hypothetical account rental and mule recruitment solicitation",
    },
    {
        "ad_text": (
            "Open a Zero-Balance Savings Account with XYZ Bank\n\n"
            "Enjoy 7% interest p.a. on your savings. Full KYC required as per RBI guidelines.\n"
            "Visit your nearest branch or apply online at https://www.xyzbank.example.com/savings.\n"
            "Documents required: Aadhaar, PAN, and address proof.\n"
            "Terms and conditions apply. DICGC insured up to ₹5,00,000.\n"
            "Customer Support: support@xyzbank.example.com | 1800-123-4567"
        ),
        "description": "Generic legitimate savings-account advertisement",
    },
    {
        "ad_text": (
            "⚠️ Cyber Safety Advisory: Protect Your Financial Identity ⚠️\n\n"
            "Beware of online ads offering to buy or rent your bank account.\n"
            "Never share your ATM PIN, CVV, or OTP with anyone.\n"
            "Banks will never ask for your password over phone or email.\n"
            "KYC is mandatory for all accounts to prevent money laundering.\n"
            "Report suspicious mule recruitment to your bank immediately.\n"
            "Official Portal: https://cybersafe.example.com/awareness"
        ),
        "description": "Financial-awareness and anti-mule educational advisory",
    },
    {
        "ad_text": (
            "Freelancer? Need a current account with easy access?\n"
            "Quick setup with minimal paperwork. Competitive transaction fees.\n"
            "Contact our team: freelancers@bizbank.example.com\n"
            "Call: +91-11-2345-6789\n\n"
            "Note: Standard verification process applies."
        ),
        "description": "Ambiguous advertisement requiring routine review",
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
    base_time = datetime.now(timezone.utc) - timedelta(days=5)

    for i, sample in enumerate(_SAMPLES):
        # Analyze with the Phase 2 detector
        result = analyze_ad(sample["ad_text"])

        record = {
            "record_id": generate_record_id(),
            "ad_text": sample["ad_text"],
            "submitted_at": (base_time + timedelta(days=i, hours=i * 2)).isoformat(),
            "analysis_mode": "rule_based",
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
            "matched_categories": result["matched_categories"],
            "evidence": result["evidence"],
            "urls": result["urls"],
            "emails": result["emails"],
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
