"""
TRACE//FIN — Demo Analyzer (Phase 1)
Deterministic, rule-based pattern matcher for demonstration purposes.

⚠ This is NOT a trained model or validated fraud detector.
  All results are labelled DEMO ANALYSIS and must not be treated
  as probability of criminal activity.

The public interface `analyze_ad(text) -> dict` is designed so that
a real ML-based detector can replace this module in later phases.
"""

import re
from typing import Any


# ── Pattern Definitions ────────────────────────────────────────────────
# Each category carries a weight, a label, and compiled regex patterns.

_CATEGORIES: list[dict[str, Any]] = [
    {
        "id": "account_sale",
        "label": "Account Sale Language",
        "weight": 25,
        "patterns": [
            re.compile(r"\b(sell|selling|buy|buying|purchase|rent|renting)\b[^\n.!?]{0,50}\b(accounts?|accts?)\b", re.I),
            re.compile(r"\b(accounts?|accts?)\b[^\n.!?]{0,50}\b(for\s+sale|available|to\s+buy|on\s+sale)\b", re.I),
            re.compile(r"\b(bank\s+accounts?|current\s+accounts?|savings\s+accounts?)\b[^\n.!?]{0,50}\b(sale|sell|buy|deal|deals)\b", re.I),
            re.compile(r"\b(sale|sell|buy)\b[^\n.!?]{0,50}\b(bank\s+accounts?|current\s+accounts?|savings\s+accounts?)\b", re.I),
        ],
    },
    {
        "id": "card_sale",
        "label": "Card Sale Language",
        "weight": 25,
        "patterns": [
            re.compile(r"\b(sell|selling|buy|buying|purchase)\b[^\n.!?]{0,50}\b(cards?|atm|debit|credit)\b", re.I),
            re.compile(r"\b(atm|debit|credit)\s*cards?\b[^\n.!?]{0,50}\b(available|sale|sell|buy)\b", re.I),
            re.compile(r"\b(cards?)\b[^\n.!?]{0,50}\b(for\s+sale|available)\b", re.I),
        ],
    },
    {
        "id": "no_kyc",
        "label": "KYC Bypass Claims",
        "weight": 25,
        "patterns": [
            re.compile(r"\bno\s+kyc\b", re.I),
            re.compile(r"\bkyc\s*(not|without|skip|bypass|free)\b", re.I),
            re.compile(r"\bwithout\s+(kyc|verification|id\s+proof|documents?)\b", re.I),
            re.compile(r"\bno\s+(id|verification|documents?)\s+required\b", re.I),
        ],
    },
    {
        "id": "guaranteed_access",
        "label": "Guaranteed / Instant Access Claims",
        "weight": 15,
        "patterns": [
            re.compile(r"\b(guaranteed|instant|immediate)\s+(access|approval|activation)\b", re.I),
            re.compile(r"\bno\s+questions\s+asked\b", re.I),
            re.compile(r"\b100\s*%\s*(guaranteed|approval|success)\b", re.I),
            re.compile(r"\bpre[\s\-]?activated\b", re.I),
        ],
    },
    {
        "id": "suspicious_contact",
        "label": "Suspicious Contact Methods",
        "weight": 10,
        "patterns": [
            re.compile(r"\b(telegram|whatsapp|signal|dm\s+me|contact\s+me)\b", re.I),
            re.compile(r"\b(wickr|dark\s*web|jabber)\b", re.I),
            re.compile(r"@[a-zA-Z0-9_]{4,}", re.I),
        ],
    },
    {
        "id": "financial_urgency",
        "label": "Urgency / Pressure Tactics",
        "weight": 10,
        "patterns": [
            re.compile(r"\b(limited\s+time|act\s+now|hurry|urgent|last\s+chance)\b", re.I),
            re.compile(r"\b(only\s+\d+\s+left|few\s+remaining|limited\s+stock)\b", re.I),
        ],
    },
    {
        "id": "payment_demand",
        "label": "Unusual Payment Demands",
        "weight": 15,
        "patterns": [
            re.compile(r"\b(crypto|bitcoin|btc|usdt|monero|xmr)\b", re.I),
            re.compile(r"\b(advance\s+payment|prepay|pay\s+first|pay\s+in\s+advance)\b", re.I),
        ],
    },
]


# ── URL / Phone / Payment-ID Extractors ────────────────────────────────

_URL_RE = re.compile(
    r"https?://[^\s<>\"']+|www\.[^\s<>\"']+",
    re.I,
)

_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?\d{1,4}[\s\-]?)(?:\(?\d{2,5}\)?[\s\-]?){1,3}\d{3,5}(?!\d)",
)

_PAYMENT_ID_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9]+",  # UPI-style IDs
)


def _extract_urls(text: str) -> list[str]:
    raw = _URL_RE.findall(text)
    cleaned = []
    for u in raw:
        # Strip trailing punctuation often caught at end of sentences
        clean_u = u.rstrip(".,;:!?)'\"")
        if clean_u:
            cleaned.append(clean_u)
    return sorted(list(set(cleaned)))


def _extract_phones(text: str) -> list[str]:
    raw = _PHONE_RE.findall(text)
    # Filter out very short matches that are likely dates or numbers
    valid = {p.strip().rstrip(".,;") for p in raw if len(re.sub(r"\D", "", p)) >= 7}
    return sorted(list(valid))


def _extract_payment_ids(text: str) -> list[str]:
    raw = _PAYMENT_ID_RE.findall(text)
    return sorted(list(set(raw)))


# ── Risk-Level & Recommendation Assignment ─────────────────────────────

def _score_to_level(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "MINIMAL"


def _derive_recommendation(risk_level: str, score: float, matched_categories: list[str]) -> str:
    """Generate human investigator recommendation."""
    if risk_level in ("CRITICAL", "HIGH"):
        return "Mandatory Investigator Review Required (High-risk indicators detected: " + ", ".join(matched_categories[:2]) + ")"
    if risk_level == "MEDIUM":
        return "Secondary Review Recommended (Ambiguous or moderate signals detected)"
    if risk_level == "LOW":
        return "Routine Verification (Low-confidence indicators)"
    return "No Immediate Review Indicated (Informational / legitimate characteristics)"


# ── Public Interface ───────────────────────────────────────────────────

def analyze_ad(text: str) -> dict:
    """
    Analyze advertisement text using deterministic pattern matching.

    Returns a dict with:
        risk_score: float (0.0 to 100.0)
        risk_level: str (CRITICAL / HIGH / MEDIUM / LOW / MINIMAL)
        matched_categories: list[str]
        evidence: dict[str, list[str]]
        urls: list[str]
        phone_numbers: list[str]
        payment_identifiers: list[str]
        review_required: bool
        review_recommendation: str
        analysis_mode: str ("demo")

    ⚠ DEMO ANALYSIS — not a trained ML model or validated fraud detector.
    """
    if not text or not text.strip():
        return {
            "risk_score": 0.0,
            "risk_level": "MINIMAL",
            "matched_categories": [],
            "evidence": {},
            "urls": [],
            "phone_numbers": [],
            "payment_identifiers": [],
            "review_required": False,
            "review_recommendation": "No text provided for analysis.",
            "analysis_mode": "demo",
        }

    matched_categories: list[str] = []
    evidence: dict[str, list[str]] = {}
    raw_score = 0.0

    for cat in _CATEGORIES:
        matches_found: list[str] = []
        for pattern in cat["patterns"]:
            found = pattern.findall(text)
            if found:
                for m in found:
                    if isinstance(m, tuple):
                        matches_found.append(" ".join(m).strip())
                    else:
                        matches_found.append(m.strip())

        if matches_found:
            matched_categories.append(cat["label"])
            # Deduplicate and sort evidence
            evidence[cat["label"]] = sorted(list(set(matches_found)))
            raw_score += cat["weight"]

    # Cap raw category score
    risk_score = min(round(raw_score, 1), 100.0)

    urls = _extract_urls(text)
    phones = _extract_phones(text)
    payment_ids = _extract_payment_ids(text)

    # Indicator presence bonuses (capped at 100)
    if urls:
        risk_score = min(risk_score + 5, 100.0)
    if phones:
        risk_score = min(risk_score + 5, 100.0)
    if payment_ids:
        risk_score = min(risk_score + 5, 100.0)

    risk_level = _score_to_level(risk_score)
    review_required = risk_score >= 40
    recommendation = _derive_recommendation(risk_level, risk_score, matched_categories)

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "matched_categories": matched_categories,
        "evidence": evidence,
        "urls": urls,
        "phone_numbers": phones,
        "payment_identifiers": payment_ids,
        "review_required": review_required,
        "review_recommendation": recommendation,
        "analysis_mode": "demo",
    }
