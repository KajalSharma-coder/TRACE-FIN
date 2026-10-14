"""
TRACE//FIN — Explainable Rule-Based Financial Advertisement Detection Engine (Phase 2)
Deterministic, explainable, rule-based analyzer for suspicious financial advertisements.

⚠ This is a rule-based detection engine and expert heuristic system.
  It is NOT a trained machine-learning model and does not claim statistical
  or probabilistic fraud predictions.
"""

import re
from typing import Any


# ── Category Constants ────────────────────────────────────────────────
CAT_ACCOUNT_CARD_SALE = "Financial Account or Card Sale"
CAT_KYC_EVASION = "KYC Evasion & Verification Bypass"
CAT_ACCOUNT_RENTAL = "Account Rental & Mule Recruitment"
CAT_SUSPICIOUS_SOLICITATION = "Suspicious Financial Solicitation"
CAT_URGENCY_SECRECY = "Urgency, Secrecy & Unrealistic Promises"

# Standard Risk Labels
LEVEL_LOW = "Low"
LEVEL_MEDIUM = "Medium"
LEVEL_HIGH = "High"
LEVEL_CRITICAL = "Critical"

STANDARD_DISCLAIMER = (
    "Automated preliminary indicators for investigator triage; not definitive proof of illegal activity. "
    "All flagged content requires verified human review and context evaluation."
)


# ── Indicator Extraction Patterns ─────────────────────────────────────

# URLs: Match http/https or www, excluding trailing punctuation
_URL_REGEX = re.compile(
    r"https?://[^\s<>\"']+|www\.[^\s<>\"']+",
    re.IGNORECASE,
)

# Email addresses: Standard RFC-compliant conservative pattern
_EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    re.IGNORECASE,
)

# Phone numbers: Conservative pattern with 7–15 digits, supports international prefixes
# Excludes single 4-digit years (e.g., 2026) and short numeric codes
_PHONE_REGEX = re.compile(
    r"(?<!\w)(?:\+?\d{1,4}[\s\-.]?)?(?:\(?\d{2,5}\)?[\s\-.]?){1,3}\d{3,5}(?!\w)",
)

# UPI / Payment Identifiers: Handles like name@upi, name@okaxis, name@paytm, etc.
# Excludes common email domains (.com, .org, .net, .edu, .gov, .in, .io, .co)
_UPI_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@(?!gmail|yahoo|outlook|hotmail|icloud|proton|protonmail|aol|zoho|mail|example)[A-Za-z0-9]{2,}\b",
    re.IGNORECASE,
)

# Specific cryptocurrency / token payment demands
_CRYPTO_REGEX = re.compile(
    r"\b(crypto|cryptocurrency|bitcoin|btc|usdt|tether|ethereum|eth|monero|xmr|binance\s+pay)\b",
    re.IGNORECASE,
)


# ── Detection Rules ───────────────────────────────────────────────────

# Category A: Financial Account or Card Sale
_PATTERNS_ACCOUNT_SALE = [
    # Explicit bank account sales
    (
        re.compile(r"\b(bank\s+accounts?|current\s+accounts?|savings\s+accounts?|payment\s+accounts?|verified\s+accounts?|merchant\s+accounts?)\b[^\n.!?]{0,60}\b(for\s+sale|available\s+for\s+sale|available\s+to\s+buy|on\s+sale|in\s+stock|available|to\s+buy)\b", re.I),
        "Explicit offer of financial accounts for sale or supply",
    ),
    (
        re.compile(r"\b(buy|buying|sell|selling|purchase|order|ordering|deal\s+in|dealing\s+in|supply|supplying|providing)\b[^\n.!?]{0,60}\b(bank\s+accounts?|current\s+accounts?|savings\s+accounts?|verified\s+accounts?|payment\s+accounts?|netbanking\s+accounts?)\b", re.I),
        "Solicitation to buy, sell, or supply bank/payment accounts",
    ),
    (
        re.compile(r"\b(accounts?\s+(with|having)\s+(online\s+banking|netbanking|internet\s+banking|login\s+credentials|full\s+kit|passbook|atm|sim|card))\b", re.I),
        "Account offered bundled with online banking credentials, SIM, or passbook",
    ),
    (
        re.compile(r"\b(full\s+kit\s+(bank\s+)?accounts?|ready[\s\-]?made\s+accounts?|stealth\s+accounts?|aged\s+accounts?)\b", re.I),
        "Sale of turnkey 'full kit' or stealth financial account packages",
    ),
    # Card sales
    (
        re.compile(r"\b(atm|debit|credit|cloned|pre[\s\-]?activated)\s*cards?\b[^\n.!?]{0,60}\b(for\s+sale|available|in\s+bulk|to\s+buy|ready\s+to\s+ship|available\s+for\s+sale)\b", re.I),
        "Offer to sell or supply debit, credit, or ATM cards",
    ),
    (
        re.compile(r"\b(buy|buying|sell|selling|purchase|order|ordering|supply|supplying)\b[^\n.!?]{0,60}\b(atm\s+cards?|debit\s+cards?|credit\s+cards?|cloned\s+cards?|card\s+dumps?|pre[\s\-]?activated\s+cards?)\b", re.I),
        "Solicitation to purchase or distribute payment/ATM cards",
    ),
]

# Category B: KYC Evasion and Verification Bypass
_PATTERNS_KYC_EVASION = [
    (
        re.compile(r"\b(no\s+kyc|without\s+kyc|skip\s+kyc|bypass\s+kyc|kyc\s*free|kyc\s+not\s+required|kyc\s+bypass)\b", re.I),
        "Explicit claim that KYC or identity checks can be avoided or bypassed",
    ),
    (
        re.compile(r"\bwithout\s+(identity\s+verification|id\s+verification|id\s+proof|documents?|verification)\b", re.I),
        "Claim of financial access without identity verification or documents",
    ),
    (
        re.compile(r"\bno\s+(identity\s+verification|id\s+verification|id\s+proof|documents?|verification)\s+(needed|required)\b", re.I),
        "Statement that identity documents or verification are not required",
    ),
    (
        re.compile(r"\b(fake\s+kyc|dummy\s+kyc|pre[\s\-]?verified\s+accounts?|pre[\s\-]?kyc|non[\s\-]?kyc)\b", re.I),
        "Reference to fake, dummy, or pre-verified KYC arrangements",
    ),
    (
        re.compile(r"\bno\s+questions\s+asked\b", re.I),
        "Claim of 'no questions asked' financial instrument provision",
    ),
]

# Category C: Account Rental, Mule Recruitment, or Third-Party Use
_PATTERNS_ACCOUNT_RENTAL = [
    (
        re.compile(r"\b(rent|renting|lease|leasing|lend|lending|share|sharing)\b[^\n.!?]{0,50}\b(your|a)\b[^\n.!?]{0,40}\b(bank\s+accounts?|current\s+accounts?|savings\s+accounts?|payment\s+accounts?|upi\s+id)\b", re.I),
        "Solicitation seeking to rent, lease, or share personal bank accounts",
    ),
    (
        re.compile(r"\b(let\s+us|allow\s+us\s+to|need\s+someone\s+to)\s+use\s+your\s+(bank\s+)?account\b", re.I),
        "Request to allow third parties to use a personal financial account",
    ),
    (
        re.compile(r"\b(bank\s+account\s+rental|rent\s+your\s+account)\b", re.I),
        "Direct mention of bank account rental arrangements",
    ),
    (
        re.compile(r"\b(receive|accept|hold)\s+(payments?|money|funds?|transfers?)\b[^\n.!?]{0,60}\b(on\s+our\s+behalf|for\s+us|and\s+(transfer|forward|send)\s+it\s+back|and\s+keep\s+(a\s+)?commission)\b", re.I),
        "Money mule recruitment: request to receive funds and forward with commission",
    ),
    (
        re.compile(r"\b(transfer|forward|send)\s+(money|funds?)\b[^\n.!?]{0,50}\b(and\s+earn\s+(a\s+)?commission|keep\s+\d+%\s+commission)\b", re.I),
        "Offer to earn commission by transferring or forwarding third-party funds",
    ),
    (
        re.compile(r"\b(daily|weekly|monthly)\s+commission\s+for\s+(using\s+your\s+account|receiving\s+(funds?|transfers?|money))\b", re.I),
        "Promised periodic commission in exchange for financial account utilization",
    ),
    (
        re.compile(r"\b(money\s+mule|cash\s*out\s+through\s+your\s+account)\b", re.I),
        "Direct reference to money mule arrangement or cashing out through third-party accounts",
    ),
]

# Category D: Suspicious Financial Solicitation
_PATTERNS_SUSPICIOUS_SOLICITATION = [
    (
        re.compile(r"\b(share|send|provide|give)\s+(your\s+)?(otp|pin|cvv|netbanking\s+password|login\s+credentials|atm\s+pin)\b", re.I),
        "Direct request for sensitive banking secrets (OTP, PIN, CVV, or password)",
    ),
    (
        re.compile(r"\b(pay\s+in\s+advance|advance\s+payment|upfront\s+fee|processing\s+fee\s+in\s+advance|transfer\s+fee\s+first)\b", re.I),
        "Demand for upfront fee or advance payment before delivering financial service",
    ),
    (
        re.compile(r"\b(transfer|pay)\s+money\s+to\s+unlock\s+(your\s+)?(funds?|loan|prize|account)\b", re.I),
        "Conditional demand to transfer money to unlock promised funds or prizes",
    ),
    (
        re.compile(r"\b(contact|dm|message|inbox|telegram|whatsapp|signal|wickr|jabber)\b[^\n.!?]{0,50}\b(to\s+(buy|purchase|order|get\s+accounts?|get\s+cards?)|for\s+rates|for\s+pricing)\b", re.I),
        "Informal messaging channel solicitation for purchasing financial instruments",
    ),
    (
        re.compile(r"\b(crypto|bitcoin|btc|usdt|monero|xmr)\s+(payments?\s+)?(only|accepted\s+for\s+accounts?)\b", re.I),
        "Solely cryptocurrency demanded for financial instrument transactions",
    ),
]

# Category E: Urgency, Secrecy, and Unrealistic Promises
_PATTERNS_URGENCY_SECRECY = [
    (
        re.compile(r"\b(don'?t\s+tell|do\s+not\s+inform|keep\s+(this\s+)?secret|keep\s+confidential|off\s+the\s+books|untraceable|100%\s+anonymous)\b", re.I),
        "Secrecy, non-disclosure, or evasion instructions",
    ),
    (
        re.compile(r"\b(guaranteed|earn|make)\s+(\$|₹|rs\.?|usd)?\s*\d+[\d,]*\s*(daily|per\s+day|weekly|hourly)\b[^\n.!?]{0,50}\b(with\s+(your|no)\s+(effort|work|investment|account))\b", re.I),
        "Unrealistic guaranteed earnings promised with minimal effort or account access",
    ),
    (
        re.compile(r"\b(100%\s*(risk[\s\-]?free|guaranteed)\s*(income|returns?|profit))\b", re.I),
        "Extravagant guarantee of '100% risk-free' financial returns",
    ),
    (
        re.compile(r"\b(only\s+\d+\s+(left|accounts?\s+remaining|slots?)|hurry\s+up|act\s+fast|urgent\s+deal|last\s+chance|immediate\s+action\s+required)\b", re.I),
        "High urgency or artificial scarcity pressure tactics",
    ),
]


# ── Contextual False-Positive & Mitigation Patterns ───────────────────

# Educational, cyber safety, regulatory, and benign awareness indicators
_PATTERNS_AWARENESS_MITIGATION = [
    re.compile(r"\b(advisory|awareness|warning|alert|beware\s+of|protect\s+yourself|tips\s+to\s+avoid|safety\s+tips|consumer\s+alert|cyber\s+safety)\b", re.I),
    re.compile(r"\b(never\s+share|never\s+rent|do\s+not\s+share|do\s+not\s+disclose|banks\s+will\s+never\s+ask|report\s+(fraud|suspicious\s+activity))\b", re.I),
    re.compile(r"\b(regulatory\s+guidelines|central\s+bank|rbi\s+guidelines|as\s+per\s+rbi|dicgc\s+insured)\b", re.I),
    re.compile(r"\b(kyc\s+is\s+mandatory|full\s+kyc\s+required|kyc\s+helps\s+prevent|understanding\s+kyc|why\s+kyc\s+matters)\b", re.I),
    re.compile(r"\b(branch\s+visit|visit\s+your\s+nearest\s+branch|authorized\s+financial\s+institution|interest\s+p\.?a\.?|per\s+annum)\b", re.I),
    re.compile(r"\b(bill\s+payment|electricity\s+bill|utility\s+bill|payment\s+reminder|due\s+date|invoice\s+due)\b", re.I),
]


# ── Extraction Functions ──────────────────────────────────────────────

def _extract_urls(text: str) -> list[str]:
    """Extract and sanitize HTTP/HTTPS and www URLs."""
    raw = _URL_REGEX.findall(text)
    cleaned = []
    for u in raw:
        clean = u.rstrip(".,;:!?)'\"")
        if clean and len(clean) > 4:
            cleaned.append(clean)
    return sorted(list(set(cleaned)))


def _extract_emails(text: str) -> list[str]:
    """Extract valid email addresses."""
    raw = _EMAIL_REGEX.findall(text)
    valid = []
    for email in raw:
        clean = email.strip().rstrip(".,;")
        # Avoid common image or file false positives
        if not re.search(r"\.(png|jpg|jpeg|gif|webp|svg|pdf)$", clean, re.I):
            valid.append(clean.lower())
    return sorted(list(set(valid)))


def _extract_phones(text: str) -> list[str]:
    """Extract phone-like numeric strings conservatively."""
    raw = _PHONE_REGEX.findall(text)
    valid = []
    for p in raw:
        clean = p.strip().rstrip(".,;")
        digits_only = re.sub(r"\D", "", clean)
        # Phone numbers should have 7 to 15 digits
        if 7 <= len(digits_only) <= 15:
            # Exclude common date patterns like 20261014
            if not (len(digits_only) == 8 and (digits_only.startswith("19") or digits_only.startswith("20"))):
                valid.append(clean)
    return sorted(list(set(valid)))


def _extract_payment_ids(text: str) -> list[str]:
    """Extract UPI-style payment identifiers."""
    raw = _UPI_REGEX.findall(text)
    valid = []
    for upi in raw:
        clean = upi.strip().rstrip(".,;")
        # Exclude typical web domain endings
        if not clean.endswith((".com", ".org", ".net", ".edu", ".gov", ".in", ".io", ".co")):
            valid.append(clean.lower())
    return sorted(list(set(valid)))


# ── Scoring & Risk Classification ─────────────────────────────────────

def _score_to_risk_level(score: int) -> str:
    """Map integer score to standardized Phase 2 risk tiers."""
    if score >= 75:
        return LEVEL_CRITICAL
    if score >= 50:
        return LEVEL_HIGH
    if score >= 25:
        return LEVEL_MEDIUM
    return LEVEL_LOW


def _build_recommendation(risk_level: str, matched_categories: list[str]) -> str:
    """Generate professional, action-oriented investigator recommendation."""
    if risk_level == LEVEL_CRITICAL:
        cats_str = ", ".join(matched_categories[:2]) if matched_categories else "severe patterns"
        return f"Priority Escalation: Critical risk indicators detected ({cats_str}). Immediate investigator review mandated."
    if risk_level == LEVEL_HIGH:
        cats_str = ", ".join(matched_categories[:2]) if matched_categories else "high-risk patterns"
        return f"High Priority: Strong indicators of suspicious financial solicitation or evasion ({cats_str}). Human review required."
    if risk_level == LEVEL_MEDIUM:
        return "Secondary Review: Moderate or ambiguous indicators detected. Contextual human evaluation recommended before action."
    return "Routine / No Action: Content exhibits legitimate, educational, or low-risk characteristics. No immediate review indicated."


# ── Main Public Function ──────────────────────────────────────────────

def analyze_ad(text: str) -> dict[str, Any]:
    """
    Analyze advertisement text using explainable rule-based pattern detection.

    Args:
        text (str): Raw advertisement, social post, or message text.

    Returns:
        dict with:
            risk_score (int): 0 to 100
            risk_level (str): 'Low' | 'Medium' | 'High' | 'Critical'
            matched_categories (list[str]): Triggered threat categories
            evidence (list[str]): Explainable matched rules and contextual explanations
            urls (list[str]): Extracted URLs
            emails (list[str]): Extracted email addresses
            phone_numbers (list[str]): Extracted phone-like numbers
            payment_identifiers (list[str]): Extracted payment identifiers (UPI, etc.)
            review_required (bool): Whether human investigator review is advised
            disclaimer (str): Neutral preliminary triage notice
            review_recommendation (str): Actionable investigator recommendation
            analysis_mode (str): Engine version marker ('rule_based')

    ⚠ Rule-Based Analyzer — Deterministic heuristics, not a trained ML model.
    """
    # Safe handling for empty, whitespace, or invalid input
    if not text or not isinstance(text, str) or not text.strip():
        return {
            "risk_score": 0,
            "risk_level": LEVEL_LOW,
            "matched_categories": [],
            "evidence": [],
            "urls": [],
            "emails": [],
            "phone_numbers": [],
            "payment_identifiers": [],
            "review_required": False,
            "disclaimer": STANDARD_DISCLAIMER,
            "review_recommendation": "No text provided for analysis.",
            "analysis_mode": "rule_based",
        }

    matched_categories: list[str] = []
    evidence: list[str] = []
    raw_score = 0

    # 1. Evaluate Category A: Financial account or card sale (Weight: 35)
    acct_sale_matched = False
    for pattern, desc in _PATTERNS_ACCOUNT_SALE:
        m = pattern.search(text)
        if m:
            acct_sale_matched = True
            snippet = m.group(0).strip()
            evidence.append(f"[{CAT_ACCOUNT_CARD_SALE}] {desc}: \"{snippet}\"")
            break
    if acct_sale_matched:
        matched_categories.append(CAT_ACCOUNT_CARD_SALE)
        raw_score += 35

    # 2. Evaluate Category B: KYC evasion and verification bypass (Weight: 30)
    kyc_matched = False
    for pattern, desc in _PATTERNS_KYC_EVASION:
        m = pattern.search(text)
        if m:
            kyc_matched = True
            snippet = m.group(0).strip()
            evidence.append(f"[{CAT_KYC_EVASION}] {desc}: \"{snippet}\"")
            break
    if kyc_matched:
        matched_categories.append(CAT_KYC_EVASION)
        raw_score += 30

    # 3. Evaluate Category C: Account rental or mule recruitment (Weight: 35)
    rental_matched = False
    for pattern, desc in _PATTERNS_ACCOUNT_RENTAL:
        m = pattern.search(text)
        if m:
            rental_matched = True
            snippet = m.group(0).strip()
            evidence.append(f"[{CAT_ACCOUNT_RENTAL}] {desc}: \"{snippet}\"")
            break
    if rental_matched:
        matched_categories.append(CAT_ACCOUNT_RENTAL)
        raw_score += 35

    # 4. Evaluate Category D: Suspicious financial solicitation (Weight: 20)
    solicitation_matched = False
    for pattern, desc in _PATTERNS_SUSPICIOUS_SOLICITATION:
        m = pattern.search(text)
        if m:
            solicitation_matched = True
            snippet = m.group(0).strip()
            evidence.append(f"[{CAT_SUSPICIOUS_SOLICITATION}] {desc}: \"{snippet}\"")
            break
    if solicitation_matched:
        matched_categories.append(CAT_SUSPICIOUS_SOLICITATION)
        raw_score += 20

    # 5. Evaluate Category E: Urgency, secrecy, and unrealistic promises (Weight: 10)
    urgency_matched = False
    for pattern, desc in _PATTERNS_URGENCY_SECRECY:
        m = pattern.search(text)
        if m:
            urgency_matched = True
            snippet = m.group(0).strip()
            evidence.append(f"[{CAT_URGENCY_SECRECY}] {desc}: \"{snippet}\"")
            break
    if urgency_matched:
        matched_categories.append(CAT_URGENCY_SECRECY)
        raw_score += 10

    # ── Contextual Combination Rules (Compounding Risk) ──────────────────
    # Combination 1: Account Sale + KYC Evasion is a hallmark of cybercrime / account dealing
    if acct_sale_matched and kyc_matched:
        raw_score += 15
        evidence.append(
            "[Compounding Risk] High-risk combination detected: Financial Account/Card Sale combined with KYC Evasion (+15 weight)."
        )

    # Combination 2: Account Rental + Urgency / Secrecy
    if rental_matched and urgency_matched:
        raw_score += 10
        evidence.append(
            "[Compounding Risk] High-risk combination detected: Mule recruitment combined with urgency/secrecy tactics (+10 weight)."
        )

    # Combination 3: Account Sale + Suspicious Solicitation (Advance Fee / Credentials)
    if acct_sale_matched and solicitation_matched:
        raw_score += 10
        evidence.append(
            "[Compounding Risk] High-risk combination detected: Account offer combined with advance payment/credential demands (+10 weight)."
        )

    # ── Contextual Mitigation & False-Positive Awareness ─────────────────
    awareness_hits = [p.search(text) for p in _PATTERNS_AWARENESS_MITIGATION]
    has_awareness = any(bool(h) for h in awareness_hits)

    if has_awareness:
        # Check if the text is primarily educational or warning rather than an actual selling solicitation
        # If there is no direct account selling or rental, or if the text starts with warning phrases
        matched_terms = [h.group(0).strip() for h in awareness_hits if h]
        first_term = matched_terms[0] if matched_terms else "advisory language"

        if not (acct_sale_matched and kyc_matched):
            # Strong mitigation when not an overt combo sale
            reduction = 45 if (acct_sale_matched or rental_matched) else 35
            raw_score = max(0, raw_score - reduction)
            evidence.append(
                f"[Contextual Mitigation] Benign educational, regulatory, or cyber safety advisory patterns detected ('{first_term}'). Suspicious risk score mitigated by -{reduction} points."
            )
        else:
            # Mild mitigation if it contains both but has mixed text
            raw_score = max(0, raw_score - 15)
            evidence.append(
                f"[Contextual Note] Text contains regulatory or warning references ('{first_term}'), but strong sale and bypass indicators remain active."
            )

    # ── Extract Threat Indicators ─────────────────────────────────────────
    urls = _extract_urls(text)
    emails = _extract_emails(text)
    phones = _extract_phones(text)
    payment_ids = _extract_payment_ids(text)

    # Indicator Presence Weighting:
    # Crucial Rule: Contact details alone NEVER imply suspiciousness.
    # If no core suspicious categories matched (raw_score == 0), contact details add 0 points.
    # If core suspicious rules DID match, presence of informal identifiers slightly amplifies triage score.
    if raw_score > 0:
        if payment_ids or _CRYPTO_REGEX.search(text):
            raw_score += 5
            evidence.append("[Indicator Context] Presence of payment/UPI/crypto handle in suspicious context (+5 weight).")
        if phones:
            raw_score += 2
        if urls:
            raw_score += 2

    # ── Cap Score and Derive Risk Level ───────────────────────────────────
    final_score = int(min(max(raw_score, 0), 100))
    risk_level = _score_to_risk_level(final_score)
    review_required = final_score >= 25
    recommendation = _build_recommendation(risk_level, matched_categories)

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "matched_categories": matched_categories,
        "evidence": evidence,
        "urls": urls,
        "emails": emails,
        "phone_numbers": phones,
        "payment_identifiers": payment_ids,
        "review_required": review_required,
        "disclaimer": STANDARD_DISCLAIMER,
        "review_recommendation": recommendation,
        "analysis_mode": "rule_based",
    }
