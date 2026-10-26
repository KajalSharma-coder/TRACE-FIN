"""
TRACE//FIN — Explainable Rule-Based Financial Advertisement Detection Engine (Phase 2)
Deterministic, explainable, rule-based analyzer for suspicious financial advertisements.

⚠ This is a rule-based detection engine and expert heuristic system.
  It is NOT a trained machine-learning model and does not claim statistical
  or probabilistic fraud predictions.
"""

import re
import unicodedata
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


def _normalize_for_matching(text: str) -> str:
    """Normalize OCR whitespace and Unicode variants without removing words."""
    normalized = unicodedata.normalize("NFKC", text)
    normalized = normalized.replace("\u00a0", " ")
    normalized = re.sub(r"[\u2010-\u2015\u2212]", "-", normalized)
    return re.sub(r"\s+", " ", normalized).strip()


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
        re.compile(
            r"\b(?:(?:bank|current|savings|payment|verified|merchant|salary|corporate|[a-zA-Z]{3,12})\s+)?accounts?\b[^\n.!?]{0,60}\b(for\s+sale|available\s+for\s+sale|available\s+to\s+buy|on\s+sale|in\s+stock|available\s+now|to\s+buy)\b",
            re.I,
        ),
        "Explicit offer of financial accounts for sale or supply",
    ),
    (
        re.compile(
            r"\b(buy|buying|sell|selling|purchase|purchasing|order|ordering|deal\s+in|dealing\s+in|supply|supplying|providing)\b[^\n.!?]{0,60}\b(?:(?:bank|current|savings|verified|payment|netbanking|corporate|[a-zA-Z]{3,12})\s+)?accounts?\b",
            re.I,
        ),
        "Solicitation to buy, sell, or supply bank/payment accounts",
    ),
    (
        re.compile(
            r"\b(accounts?\s+(with|having)\s+(online\s+banking|netbanking|internet\s+banking|login\s+credentials|full\s+kit|passbook|atm|sim|card))\b",
            re.I,
        ),
        "Account offered bundled with online banking credentials, SIM, or passbook",
    ),
    (
        re.compile(
            r"\b(full\s+kit\s+(bank\s+)?accounts?|ready[\s\-]?made\s+accounts?|stealth\s+accounts?|aged\s+accounts?)\b",
            re.I,
        ),
        "Sale of turnkey 'full kit' or stealth financial account packages",
    ),
    # Card sales
    (
        re.compile(
            r"\b(atm|debit|credit|cloned|pre[\s\-]?activated)\s*cards?\b[^\n.!?]{0,60}\b(for\s+sale|available|in\s+bulk|to\s+buy|ready\s+to\s+ship|available\s+for\s+sale)\b",
            re.I,
        ),
        "Offer to sell or supply debit, credit, or ATM cards",
    ),
    (
        re.compile(
            r"\b(buy|buying|sell|selling|purchase|order|ordering|supply|supplying)\b[^\n.!?]{0,60}\b(atm\s+cards?|debit\s+cards?|credit\s+cards?|cloned\s+cards?|card\s+dumps?|pre[\s\-]?activated\s+cards?)\b",
            re.I,
        ),
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
    (
        re.compile(r"\b(?:fully\s+|pre[\s\-]?|already\s+)?kyc\s+verified\b[^\n.!?]{0,40}\baccounts?\b", re.I),
        "Turnkey KYC-verified financial account offered for third-party acquisition",
    ),
    (
        re.compile(
            r"\b((?:guaranteed|100%\s*guaranteed|instant)\s+(?:loan\s+)?(?:approval|sanction)\b[^\n.!?]{0,50}\b(?:no\s+(?:cibil|credit|income|document(?:ation)?)\s+checks?|without\s+(?:cibil|credit|income|verification))|(?:no\s+(?:cibil|credit|income|salary)\s+checks?|without\s+(?:cibil|credit|income\s+proof|verification))\b[^\n.!?]{0,50}\b(?:guaranteed|instant|100%|immediate)\s+(?:loan|approval|sanction))\b",
            re.I,
        ),
        "Guaranteed loan approval combined with explicit bypass of credit, CIBIL, or documentation checks",
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
        re.compile(
            r"\b(?:use|using|provide|providing)\s+(?:your|a|the|personal)\s+"
            r"(?:personal\s+)?(?:bank|current|savings|payment)\s+accounts?\b"
            r"[^.!?]{0,100}\b(?:receive|accept|forward|transfer|send)\b",
            re.I,
        ),
        "Instruction to use a personal bank account to receive or forward payments",
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
        re.compile(
            r"\b(?:receive|accept|forward|transfer|send)\s+(?:incoming\s+)?"
            r"(?:payments?|money|funds?|transfers?)\b[^.!?]{0,70}"
            r"\b(?:forward|transfer|send|to\s+other\s+accounts?)\b",
            re.I,
        ),
        "Instruction to receive and forward incoming payments to other accounts",
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
        re.compile(r"\b(money\s+mule|cash\s*out\s+through\s+your\s+account|instant\s+cashout|cash\s*out\s+service|cashout\s+service)\b", re.I),
        "Direct reference to money mule arrangement, illicit cashout service, or third-party fund extraction",
    ),
    (
        re.compile(r"\b(need|seeking|looking\s+for|require)\b[^\n.!?]{0,40}\b(?:(?:bank|current|savings|corporate|[a-zA-Z]{3,12})\s+)?accounts?\b[^\n.!?]{0,50}\b(to\s+receive|for\s+transfers?|for\s+transactions?|for\s+hawala|for\s+use|for\s+rent|for\s+cashout|for\s+company\s+funds?)\b", re.I),
        "Solicitation seeking third-party bank accounts for fund forwarding or transactions",
    ),
    (
        re.compile(r"\b(keep\s+\d+%\s+(?:daily\s+)?commission|\d+%\s+daily\s+commission|daily\s+commission\s+for\s+receiving)\b", re.I),
        "Commission cut promised for receiving third-party funds or account access",
    ),
]

# Category D: Suspicious Financial Solicitation
_PATTERNS_SUSPICIOUS_SOLICITATION = [
    (
        re.compile(
            r"\b(?:cashback|cash\s*back|reward|prize|gift)\b[^\n]{0,100}"
            r"\b(?:won|winner|claim|claimed|click|collect)\b[^\n]{0,100}"
            r"\b(?:upi|otp|verification\s+code|pin|payment\s+details?)\b"
            r"|\b(?:upi|otp|verification\s+code|pin)\b[^\n]{0,100}"
            r"\b(?:cashback|cash\s*back|reward|prize|gift)\b[^\n]{0,100}"
            r"\b(?:claim|click|verify|complete)\b",
            re.I,
        ),
        "Unsolicited reward or cashback conditioned on clicking or financial verification",
    ),
    (
        re.compile(
            r"\b(?:your|the)\s+(?:bank\s+)?account\b[^\n]{0,90}"
            r"\b(?:blocked|suspended|closed|deactivated|restricted)\b[^\n]{0,90}"
            r"\b(?:verify|confirm|update|click|visit)\b"
            r"|\b(?:verify|confirm|update)\b[^\n]{0,100}"
            r"\b(?:account\s+(?:will\s+be\s+)?(?:blocked|suspended|closed|deactivated)|avoid\s+(?:account\s+)?suspension)\b",
            re.I,
        ),
        "Account-block threat paired with an urgent verification or link action",
    ),
    (
        re.compile(r"\b(share|send|provide|give|enter|submit|type|forward|tell|disclose|request(?:s|ed|ing)?|ask(?:s|ed|ing)?\s+for)\b[^\n.!?]{0,70}\b(your\s+)?(otp|one[\s\-]?time\s+passwords?|verification\s+codes?|mpin|upi\s+pins?|atm\s+pins?|cvv\d?|netbanking\s+(?:login\s+)?passwords?|banking\s+(?:login\s+)?passwords?|login\s+credentials?|banking\s+credentials?|internet\s+banking\s+passwords?)\b", re.I),
        "Direct request or harvesting of sensitive banking secrets (OTP, PIN, CVV, or password)",
    ),
    (
        re.compile(r"\b(pay\s+in\s+advance|advance\s+payment|upfront\s+fee|processing\s+fee\s+in\s+advance|transfer\s+fee\s+first|loan\s+(?:release|clearance)\s+fees?|(?:advance|upfront)\s+loan\s+(?:processing|approval|disbursement)\s+fees?|(?:pay|deposit|transfer)\s+(?:upfront|in\s+advance|advance)\b[^\n.!?]{0,40}\b(?:fee|charges?|amount|deposit)\b[^\n.!?]{0,40}\b(?:to\s+(?:release|disburse|approve|unlock|receive|get)|before\s+(?:disbursement|loan\s+release|release))|(?:advance|upfront)\s+(?:processing\s+fee|fee|payment|charges?|deposit)\s+(?:for|before)\s+(?:loan|funds?|disbursement))\b", re.I),
        "Demand for upfront fee or advance payment before delivering financial service or loan release",
    ),
    (
        re.compile(r"\b(transfer|pay)\s+money\s+to\s+unlock\s+(your\s+)?(funds?|loan|prize|account)\b", re.I),
        "Conditional demand to transfer money to unlock promised funds or prizes",
    ),
    (
        re.compile(
            r"(?:(?:guaranteed|instant|limited)\b[^.!?]{0,100}"
            r"\b(?:activation|registration|joining|processing)\s+"
            r"(?:bonus\s*/\s*)?(?:fee|charge)\b|"
            r"\b(?:activation|registration|joining|processing)\s+"
            r"(?:bonus\s*/\s*)?(?:fee|charge)\b[^.!?]{0,100}"
            r"\b(?:guaranteed|earnings?|income|account|transfer|receive)\b)",
            re.I,
        ),
        "Activation or registration fee linked to guaranteed earnings or account transfers",
    ),
    (
        re.compile(r"\b(?:activation|registration|joining|processing)\s+(?:bonus\s*/\s*)?(?:fee|charge)\b", re.I),
        "Activation or registration fee requested in a financial solicitation",
    ),
    (
        re.compile(r"\b(contact|dm|message|inbox|telegram|whatsapp|signal|wickr|jabber)\b[^\n.!?]{0,50}\b(to\s+(buy|purchase|order|get\s+accounts?|get\s+cards?)|for\s+rates|for\s+pricing)\b", re.I),
        "Informal messaging channel solicitation for purchasing financial instruments",
    ),
    (
        re.compile(r"\b(crypto|bitcoin|btc|usdt|monero|xmr)\s+(payments?\s+)?(only|accepted\s+for\s+accounts?)\b", re.I),
        "Solely cryptocurrency demanded for financial instrument transactions",
    ),
    (
        re.compile(r"\b(hawala(\s+transactions?|\s+network|\s+channel|\s+money)?|undocumented\s+transfers?|black\s+money\s+transfers?)\b", re.I),
        "Solicitation for hawala or illicit informal value transfer transactions",
    ),
]

# Category E: Urgency, Secrecy, and Unrealistic Promises
_PATTERNS_URGENCY_SECRECY = [
    (
        re.compile(r"\b(don'?t\s+tell|do\s+not\s+inform|avoid\s+(?:contacting|informing)\s+(?:the\s+)?bank|keep\s+(this\s+)?secret|keep\s+confidential|off\s+the\s+books|untraceable|100%\s+anonymous)\b", re.I),
        "Secrecy, non-disclosure, or evasion instructions",
    ),
    (
        re.compile(
            r"\bguaranteed\s+(?:earnings?|income)\s+(?:of\s+)?"
            r"(?:₹|rs\.?|usd|\$)?\s*\d+[\d,]*(?:\s*[-–—]\s*"
            r"(?:₹|rs\.?|usd|\$)?\s*\d+[\d,]*)?\s*"
            r"(?:daily|per\s+day|weekly|monthly|per\s+month|hourly)\b",
            re.I,
        ),
        "Guaranteed earnings or income promise with a monetary amount",
    ),
    (
        re.compile(
            r"\b(?:guaranteed\s+)?(?:earnings?|income|earn|make)\s+(?:of\s+)?"
            r"(?:₹|rs\.?|usd|\$)?\s*\d+[\d,]*(?:\s*[-–—]\s*"
            r"(?:₹|rs\.?|usd|\$)?\s*\d+[\d,]*)?\s*"
            r"(?:daily|per\s+day|weekly|monthly|per\s+month|hourly)\b"
            r"[^.!?]{0,80}\b(?:with\s+(?:your|no)\s+(?:effort|work|investment|account)|"
            r"guaranteed|personal\s+account|limited\s+seats?)\b",
            re.I,
        ),
        "Unrealistic guaranteed earnings promised with minimal effort or account access",
    ),
    (
        re.compile(r"\b(100%\s*(risk[\s\-]?free|guaranteed)\s*(income|returns?|profit))\b", re.I),
        "Extravagant guarantee of '100% risk-free' financial returns",
    ),
    (
        re.compile(r"\b(only\s+\d+\s+(left|accounts?\s+remaining|slots?)|limited\s+seats?|hurry\s+up|act\s+fast|urgent\s+deal|last\s+chance|immediate\s+action\s+required|(?:click|claim|verify|respond)\s+(?:now|immediately|today)|limited[- ]time\s+(?:offer|reward|claim))\b", re.I),
        "High urgency or artificial scarcity pressure tactics",
    ),
]


# ── Contextual False-Positive & Mitigation Patterns ───────────────────

# Educational, cyber safety, regulatory, and benign awareness indicators
_PATTERNS_AWARENESS_MITIGATION = [
    re.compile(r"\b(security\s+advisory|fraud\s+awareness|scam\s+warning|beware\s+of|protect\s+yourself|tips\s+to\s+avoid|safety\s+tips|consumer\s+alert|cyber\s+safety)\b", re.I),
    re.compile(r"\b(never\s+share|never\s+rent|do\s+not\s+share|do\s+not\s+disclose|banks\s+will\s+never\s+ask|report\s+(fraud|suspicious\s+activity))\b", re.I),
    re.compile(r"\b(regulatory\s+guidelines|central\s+bank|rbi\s+guidelines|as\s+per\s+rbi|dicgc\s+insured)\b", re.I),
    re.compile(r"\b(kyc\s+is\s+mandatory|full\s+kyc\s+required|kyc\s+helps\s+prevent|understanding\s+kyc|why\s+kyc\s+matters)\b", re.I),
    re.compile(r"\b(branch\s+visit|visit\s+your\s+nearest\s+branch|authorized\s+financial\s+institution|interest\s+p\.?a\.?|per\s+annum)\b", re.I),
    re.compile(r"\b(bill\s+payment|electricity\s+bill|utility\s+bill|payment\s+reminder|due\s+date|invoice\s+due)\b", re.I),
    re.compile(r"\b(processing\s+fee\s+applicable|as\s+per\s+bank\s+(policy|terms|norms)|nominal\s+processing\s+fee|terms\s+and\s+conditions\s+apply|t&c\s+apply|interest\s+rates?\s+apply)\b", re.I),
    re.compile(r"\b(loan\s+processing\s+fees?|interest\s+rates?|flexible\s+tenures?|calculate\s+emi|pre-?approved\s+(?:loans?|offers?)|apply\s+online|home\s+loans?|personal\s+loans?|car\s+loans?|education\s+loans?|fixed\s+deposits?|savings\s+accounts?|annual\s+percentage\s+rate|apr|eligibility\s+criteria)\b", re.I),
]

# A conventional one-time-code notification contains the code validity and a
# clear non-disclosure instruction, without links or an action request. This
# narrow context helps avoid flagging transactional OTP notices solely because
# bank-brand/OTP terms are correlated with scams in small training corpora.
_LEGITIMATE_OTP_NOTICE = re.compile(
    r"^(?!.*(?:https?://|www\.|click\s+here|verify\s+now|account\s+(?:will\s+be\s+)?(?:blocked|suspended)|claim\s+(?:your\s+)?(?:reward|cashback)))"
    r"(?=.*\b(?:your\s+)?otp\b[^\n.!?]{0,50}\b(?:is|:)\s*\d{4,8}\b)"
    r"(?=.*\bvalid\s+for\s+\d+\s*(?:seconds?|secs?|minutes?|mins?)\b)"
    r"(?=.*\b(?:do\s+not\s+share|never\s+share)\b)"
    r".*$",
    re.I | re.S,
)


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
    if matched_categories:
        return "Low Risk: Minor indicators present without compounding risk. Routine monitoring."
    return "No configured rules matched. Verify with statistical models or manual review if novel threats are suspected."


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
            matched_rules (list[dict]): Details of triggered rules and snippets
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
            "matched_rules": [],
            "evidence": [],
            "urls": [],
            "emails": [],
            "phone_numbers": [],
            "payment_identifiers": [],
            "review_required": False,
            "disclaimer": STANDARD_DISCLAIMER,
            "review_recommendation": "No text provided for analysis.",
            "analysis_mode": "rule_based",
            "legitimate_transactional_otp": False,
        }

    # OCR engines can emit compatibility Unicode forms, non-breaking spaces,
    # line breaks, and typographic dashes. Normalize only for matching so
    # equivalent visual text follows the same explainable rules.
    text = _normalize_for_matching(text)
    matched_categories: list[str] = []
    matched_rules: list[dict[str, Any]] = []
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
            matched_rules.append({
                "category": CAT_ACCOUNT_CARD_SALE,
                "rule_name": desc,
                "evidence": snippet,
                "weight": 35,
            })
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
            matched_rules.append({
                "category": CAT_KYC_EVASION,
                "rule_name": desc,
                "evidence": snippet,
                "weight": 30,
            })
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
            matched_rules.append({
                "category": CAT_ACCOUNT_RENTAL,
                "rule_name": desc,
                "evidence": snippet,
                "weight": 35,
            })
            break
    if rental_matched:
        matched_categories.append(CAT_ACCOUNT_RENTAL)
        raw_score += 35

    # 4. Evaluate Category D: Suspicious financial solicitation (Weight: 20)
    solicitation_matched = False
    for pattern, desc in _PATTERNS_SUSPICIOUS_SOLICITATION:
        if (
            desc == "Activation or registration fee requested in a financial solicitation"
            and not re.search(r"\b(?:account|transfer|receive|earnings?|guaranteed|otp|limited)\b", text, re.I)
        ):
            # An activation fee by itself can be legitimate; require adjacent
            # financial-solicitation context before treating it as a signal.
            continue
        m = pattern.search(text)
        if m:
            solicitation_matched = True
            snippet = m.group(0).strip()
            evidence.append(f"[{CAT_SUSPICIOUS_SOLICITATION}] {desc}: \"{snippet}\"")
            matched_rules.append({
                "category": CAT_SUSPICIOUS_SOLICITATION,
                "rule_name": desc,
                "evidence": snippet,
                "weight": 20,
            })
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
            matched_rules.append({
                "category": CAT_URGENCY_SECRECY,
                "rule_name": desc,
                "evidence": snippet,
                "weight": 10,
            })
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

    legitimate_transactional_otp = bool(
        raw_score == 0
        and not matched_rules
        and _LEGITIMATE_OTP_NOTICE.search(text)
    )
    if legitimate_transactional_otp:
        evidence.append(
            "[Contextual Legitimate Template] One-time-code notice includes an expiry and non-disclosure instruction, with no link or request to take action."
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

    # ── State clearly if no rules matched ─────────────────────────────────
    evidence = list(dict.fromkeys(evidence))
    if not evidence:
        evidence = ["No configured rules matched."]

    # ── Cap Score and Derive Risk Level ───────────────────────────────────
    final_score = int(min(max(raw_score, 0), 100))
    risk_level = _score_to_risk_level(final_score)
    review_required = final_score >= 25
    recommendation = _build_recommendation(risk_level, matched_categories)

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "matched_categories": matched_categories,
        "matched_rules": matched_rules,
        "evidence": evidence,
        "urls": urls,
        "emails": emails,
        "phone_numbers": phones,
        "payment_identifiers": payment_ids,
        "review_required": review_required,
        "disclaimer": STANDARD_DISCLAIMER,
        "review_recommendation": recommendation,
        "analysis_mode": "rule_based",
        "has_mitigation": has_awareness,
        "legitimate_transactional_otp": legitimate_transactional_otp,
    }


# ── Unified Final Decision Strategy ────────────────────────────────────

def compute_unified_verdict(
    rule_result: dict[str, Any],
    ml_result: dict[str, Any] | None = None,
    hf_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Synthesize rule heuristics (Phase 2), TF-IDF ML baseline (Phase 3), and DistilBERT (Phase 4)
    into a single prominent, consistent final verdict and risk score (0-100).

    Verdict Tiers (Standardized):
      - 'HIGH RISK' (Score 70-100): Confirmed violations or multi-engine consensus threat.
      - 'MEDIUM RISK' (Score 30-69): Moderate rule indicators or engine divergence (manual review required).
      - 'LOW RISK' (Score 0-29): Benign, educational, or standard transactional content.

    Governance:
      - Never labels an ad definitively fraudulent (decision support only).
      - Reconciles engine divergence conservatively without contradictory messaging.
      - Disagreements route to MEDIUM RISK (Manual Review Required).
    """
    rule_score = int(rule_result.get("risk_score", 0)) if rule_result else 0
    rule_level = str(rule_result.get("risk_level", "Low")).capitalize() if rule_result else "Low"
    rule_cats = rule_result.get("matched_categories", []) if rule_result else []
    has_rule_threat = rule_score >= 25
    has_mitigation = bool(rule_result and rule_result.get("has_mitigation")) or any(
        "[Contextual Mitigation]" in str(ev) for ev in ((rule_result.get("evidence") if rule_result else []) or [])
    )

    ml_avail = bool(ml_result and ml_result.get("available", ml_result.get("risk_label") is not None))
    ml_high = bool(ml_avail and ml_result.get("risk_label") == "High Risk")
    ml_conf = ml_result.get("confidence") if ml_avail else None

    hf_avail = bool(hf_result and hf_result.get("available", hf_result.get("risk_label") is not None))
    hf_high = bool(hf_avail and hf_result.get("risk_label") == "High Risk")
    hf_conf = hf_result.get("confidence") if hf_avail else None

    models_available = int(ml_avail) + int(hf_avail)
    models_high = int(ml_high) + int(hf_high)
    legitimate_otp_notice = bool(
        rule_result
        and rule_result.get("legitimate_transactional_otp")
        and rule_score == 0
        and not rule_result.get("matched_rules")
    )

    # A narrowly recognized informational OTP template is not a credential
    # request. It cannot suppress any positive heuristic evidence.
    if legitimate_otp_notice:
        final_verdict = "LOW RISK"
        final_score = 0
        badge_color = "#22c55e"
        consensus_status = "Recognized Transactional OTP Notice"
        explanation = (
            "This matches an informational one-time-code notice with an expiry and a do-not-share instruction. "
            "No link, action request, or suspicious financial solicitation was detected."
        )
        recommendation = "Routine: Never share the code. If you did not request it, contact your bank through its official channel."
        investigation_status = "Closed"
        review_required = False

    # 1. Consensus Threat: High rule score confirmed by models, or critical overt rule violation
    elif (rule_score >= 50 and models_high >= 1) or rule_score >= 70 or (rule_score >= 35 and models_high == 2):
        final_verdict = "HIGH RISK"
        final_score = max(rule_score, 75 if models_high >= 1 else rule_score)
        badge_color = "#ef4444"
        consensus_status = "Consensus Threat"
        if models_high >= 1:
            explanation = (
                f"Strong suspicious indicators detected across {len(rule_cats)} heuristic "
                f"category{'s' if len(rule_cats) != 1 else ''} and confirmed by machine learning models."
            )
        else:
            explanation = f"Severe suspicious financial indicators detected by heuristic rules ({', '.join(rule_cats[:2])})."
        recommendation = "Priority Action: Immediate human review mandated. Preserve all extracted payment, phone, and URL identifiers."
        investigation_status = "Escalated"
        review_required = True

    # 2. Rule Threat with Model Divergence: Rules fired but models predicted Safe
    elif has_rule_threat and models_high == 0:
        if rule_score >= 50:
            final_verdict = "HIGH RISK"
            final_score = rule_score
            badge_color = "#f97316"
            consensus_status = "Rule Violation (Model Divergence)"
            explanation = (
                "High-risk patterns detected by heuristic rules. Statistical models diverged, "
                "indicating novel criminal phrasing outside training templates."
            )
            recommendation = "Priority Review: Evaluate triggered heuristic evidence and verified matched phrases."
            investigation_status = "Open"
            review_required = True
        else:
            final_verdict = "MEDIUM RISK"
            final_score = max(rule_score, 35)
            badge_color = "#eab308"
            consensus_status = "Moderate Rule Indicators"
            explanation = (
                "Moderate suspicious indicators detected by heuristic rules. "
                "Contextual human review recommended before escalation."
            )
            recommendation = "Secondary Review: Evaluate context to confirm whether content is an evasive financial solicitation."
            investigation_status = "Reviewing"
            review_required = True

    # 3. Rule indicators with partial model confirmation: never downgrade to LOW RISK.
    # A rule score >=25 means a configured threat pattern matched. If only one
    # model is high (or the score is below the high-risk consensus threshold),
    # preserve a MEDIUM RISK result and require human review. The score remains
    # the explainable heuristic score: model availability/alerts affect the
    # verdict and workflow, but must not replace the measured rule evidence with
    # an arbitrary fallback such as 40.
    elif has_rule_threat and models_high >= 1:
        final_verdict = "MEDIUM RISK"
        final_score = rule_score
        badge_color = "#eab308"
        consensus_status = "Rule Indicators + Model Alert (Manual Review Required)"
        model_names = []
        if ml_high:
            model_names.append("TF-IDF ML")
        if hf_high:
            model_names.append("DistilBERT")
        models_str = " & ".join(model_names)
        explanation = (
            f"Heuristic rules detected suspicious financial indicators and {models_str} flagged the content, "
            "but the evidence does not meet the configured HIGH RISK consensus threshold. Human review is required."
        )
        recommendation = "Manual Review Required: Evaluate matched rule evidence and model alerts before taking action."
        investigation_status = "Reviewing"
        review_required = True

    # 4. Model Alert with No Rules Matched: Ambiguity / Divergence (Conservative Manual Review)
    elif not has_rule_threat and models_high >= 1:
        if (
            has_mitigation
            and rule_score == 0
            and not (rule_result or {}).get("matched_rules")
            and not ml_high
            and models_high == 1
        ):
            final_verdict = "LOW RISK"
            final_score = 0
            badge_color = "#22c55e"
            consensus_status = "Mitigated Legitimate Content"
            explanation = (
                "Verified legitimate financial institution disclosures and standard product terms detected. "
                "Single-model statistical divergence is overridden as benign."
            )
            recommendation = "Routine: Verified legitimate banking or financial disclosure. No action required."
            investigation_status = "Closed"
            review_required = False
        else:
            final_verdict = "MEDIUM RISK"
            # Deterministic combination: routed to 50 (if both models flag) or 40 (if 1 model flags)
            final_score = 50 if models_high >= 2 else 40
            badge_color = "#eab308"
            has_matched_rule_evidence = bool((rule_result or {}).get("matched_rules"))
            consensus_status = (
                "Mitigated Rule Evidence + Model Alert (Manual Review Required)"
                if has_matched_rule_evidence else
                "Model Alert (Manual Review Required)"
            )
            model_names = []
            if ml_high:
                model_names.append("TF-IDF ML")
            if hf_high:
                model_names.append("DistilBERT")
            models_str = " & ".join(model_names)
            if has_matched_rule_evidence:
                explanation = (
                    f"Statistical classifier ({models_str}) flagged suspicious vocabulary patterns. "
                    "Heuristic rule evidence was reduced by contextual awareness mitigation, but remains visible; "
                    "manual review is required to resolve the disagreement."
                )
                recommendation = (
                    "Manual Review Required: Review the matched heuristic evidence and awareness context "
                    "alongside the model alert before taking action."
                )
            else:
                explanation = (
                    f"Statistical classifier ({models_str}) flagged suspicious vocabulary patterns, "
                    f"but no configured heuristic rules matched. Manual review is required to verify legitimacy."
                )
                recommendation = "Manual Review Required: Content flagged by statistical classifier but not matched by explicit heuristic rules. Verify context before taking action."
            investigation_status = "Reviewing"
            review_required = True

    # 5. No engine could assess benignity. A missing model is not a safe
    # prediction; without rule indicators there is not enough evidence to
    # produce a LOW RISK verdict.
    elif models_available == 0:
        final_verdict = "INSUFFICIENT EVIDENCE"
        final_score = None
        badge_color = "#94a3b8"
        consensus_status = "Models Unavailable; Rule Review Only"
        explanation = (
            "No configured heuristic threat patterns matched, and no statistical model was available. "
            "This is an incomplete assessment, not a confirmed low-risk result."
        )
        recommendation = (
            "Manual Review Required: Check model availability and review the submitted content before treating it as benign."
        )
        investigation_status = "Reviewing"
        review_required = True

    # 6. Consensus Low Risk / Benign: Neither rules nor available models flagged
    else:
        final_verdict = "LOW RISK"
        final_score = min(rule_score, 24)
        badge_color = "#22c55e"
        consensus_status = "Consensus Benign / Safe"
        explanation = "No suspicious financial solicitation, account trading, or KYC evasion patterns were detected."
        recommendation = "Routine: Content displays standard transaction or educational language. No investigative escalation required."
        investigation_status = "Closed"
        review_required = False

    return {
        "final_verdict": final_verdict,
        "final_score": int(min(max(final_score, 0), 100)) if final_score is not None else None,
        "explanation": explanation,
        "recommendation": recommendation,
        "investigation_status": investigation_status,
        "review_required": review_required,
        "badge_color": badge_color,
        "consensus_status": consensus_status,
        "rule_score": rule_score,
        "rule_level": rule_level,
        "ml_label": ml_result.get("risk_label") if ml_avail else None,
        "ml_confidence": ml_conf,
        "hf_label": hf_result.get("risk_label") if hf_avail else None,
        "hf_confidence": hf_conf,
    }
