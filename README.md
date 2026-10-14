# TRACE//FIN

**Detect signals. Connect evidence. Prioritize investigations.**

AI-assisted financial cybercrime intelligence platform — Phase 2: Explainable Rule-Based Detection Engine.

---

## Official Problem Statement

- **Problem ID:** SKIT002
- **Title:** AI & Cybercrime — AI-Based Detection of Suspicious Financial Advertisements

The platform identifies suspicious online advertisements and posts promoting the illicit sale, rental, or misuse of bank accounts, ATM cards, debit cards, credit cards, current accounts, savings accounts, or other financial access instruments.

The complete platform roadmap:
- Detection of financial account and card-sale language.
- Identification of high-risk claims (No KYC, guaranteed access, unauthorized account-use arrangements).
- Detection of account rental, mule recruitment, and third-party forwarding arrangements.
- Extraction of threat indicators (URLs, emails, phone numbers, UPI/payment identifiers, advance payment demands).
- Contextual false-positive mitigation for educational, regulatory, and benign awareness texts.
- OCR extraction of text embedded within advertisement screenshots (Phase 3).
- Coordinated campaign and relationship discovery across shared identifiers (Phase 4).
- Labelled training dataset, statistical machine learning models, and evaluation benchmarking (Future Phases).
- Decision-support prioritization for fraud and cybercrime investigators.

> **Investigator Mandate:** A suspicious signal is **not** proof of a crime. Human review and verified due process remain essential parts of every workflow. Automated scores are preliminary triage indicators, not definitive proof of illegal activity.

---

## Product Identity

- **Product Name:** TRACE//FIN
- **Product Category:** Financial Threat Intelligence
- **Tagline:** "Detect signals. Connect evidence. Prioritize investigations."
- **Aesthetic:** Modern, restrained cybersecurity intelligence console (dark navy `#0f1724`, slate panels, restrained cyan `#06b6d4` highlights).

---

## Phase 2: Explainable Rule-Based Detection Engine

Phase 2 replaces Phase 1's isolated keyword scoring with an **explainable, deterministic rule-based detection engine** implemented in `src/detector.py`.

### Distinction: Rule-Based Engine vs. Machine Learning

> **Engineering Honesty:** Phase 2 uses a **rule-based expert heuristic system**, NOT a trained machine-learning model. It does not output statistical confidence, predictive fraud probabilities, or benchmarked classification metrics. Machine learning models will be integrated in subsequent phases using a labelled dataset.

### Detection Categories

The rule engine inspects input across five modular threat categories:

1. **Financial Account or Card Sale (`Financial Account or Card Sale`):**
   - Detects contextual phrases offering to sell, purchase, or supply bank accounts (savings, current, merchant), accounts with online banking credentials / full kits, or debit / credit / ATM cards.
   - Guardrails prevent flagging ordinary banking activities like opening a legitimate savings account or applying for bank debit cards.
2. **KYC Evasion & Verification Bypass (`KYC Evasion & Verification Bypass`):**
   - Detects claims that identity verification, document submission, or KYC can be skipped, bypassed, or avoided ("no KYC", "without verification", "fake KYC", "dummy accounts").
   - Combined with account sales, this triggers a high-severity compounding risk multiplier.
3. **Account Rental & Mule Recruitment (`Account Rental & Mule Recruitment`):**
   - Identifies money mule recruitment: solicitations seeking to rent, lease, or borrow personal bank accounts or UPI handles, or arrangements to receive funds and forward them in exchange for a commission.
4. **Suspicious Financial Solicitation (`Suspicious Financial Solicitation`):**
   - Identifies requests for sensitive banking secrets (OTPs, PINs, passwords, CVV), upfront fees, advance payments before service delivery, and informal off-platform contact for account purchases.
5. **Urgency, Secrecy & Unrealistic Promises (`Urgency, Secrecy & Unrealistic Promises`):**
   - Flags non-disclosure pressure ("don't tell your bank", "off the books"), artificial scarcity ("only 2 slots left, act fast"), and impossible guaranteed passive income tied to account usage.
   - *Limitation:* Urgency or generic promises alone never trigger a High or Critical risk classification.

### Threat Entity Extraction

The engine extracts four structured indicator types using conservative patterns:
- **HTTP / HTTPS / www URLs** (with trailing punctuation stripping).
- **Email Addresses** (RFC-compliant regex, filtering non-email file artifacts).
- **Phone-Like Strings** (7 to 15 digits, supporting international prefixes, excluding single years or dates).
- **Payment Identifiers** (UPI-style handles such as `name@okaxis`, `merchant@upi`, `seller@paytm`, and cryptocurrency mentions).

> **Indicator Principle:** Extracted contact details and payment identifiers are **investigative leads for human review, not proof of wrongdoing**. Ordinary contact details alone contribute zero risk points unless suspicious threat patterns are detected.

### False-Positive Awareness & Mitigation

The detector evaluates text for educational, regulatory, and benign contexts:
- Articles explaining KYC regulations (e.g. RBI guidelines).
- Official banking advertisements (interest p.a., DICGC insurance, branch visit).
- Routine payment reminders (utility bills, invoices).
- Cybersecurity awareness advisories ("never share your OTP", "beware of mule recruitment").

When advisory or legitimate context is detected without overt account trafficking combinations, the engine applies contextual score mitigations and documents the mitigation rationale in the explainable evidence list.

---

## Standardized Risk Tiers & Scoring

Scores are deterministic integers bounded between 0 and 100:

| Risk Tier | Score Range | Meaning & Triage Recommendation |
|---|---|---|
| **Low** | 0 – 24 | Content exhibits legitimate, educational, or low-risk characteristics. No priority review indicated. |
| **Medium** | 25 – 49 | Moderate or ambiguous indicators detected. Contextual human evaluation recommended before action. |
| **High** | 50 – 74 | Strong indicators of suspicious financial solicitation or verification evasion. Investigator review required. |
| **Critical** | 75 – 100 | Critical risk indicators (e.g., account trafficking bundled with KYC bypass). Immediate investigator review mandated. |

---

## Project Structure

```
trace-fin/
├── app.py                          # Main dashboard entry point
├── config.py                       # Paths, risk thresholds, design tokens, app version
├── requirements.txt                # Dependencies (streamlit, pandas, plotly, pytest)
├── README.md                       # Comprehensive platform documentation
├── .gitignore                      # Exclusions for .venv, __pycache__, SQLite DB, secrets
├── .streamlit/
│   └── config.toml                 # Dark theme & custom navigation configuration
├── assets/                         # Static assets directory
├── data/                           # SQLite database storage
│   └── tracefin.db                 # SQLite database (WAL mode, persistent)
├── src/
│   ├── __init__.py
│   ├── database.py                 # SQLite CRUD, column migrations, metrics & normalization
│   ├── detector.py                 # Phase 2: Explainable rule-based detection engine
│   ├── demo_analyzer.py            # Phase 1: Legacy pattern matcher (preserved for reference)
│   ├── sample_data.py              # Phase 2: Synthetic sample suite covering all categories
│   └── ui_components.py            # Reusable UI cards, 4-column indicators, dossier view
├── pages/
│   ├── 1_Analyze_Advertisement.py  # Advertisement text intake & rule-based triage
│   ├── 2_Investigation_Cases.py    # Case management & lifecycle status updates
│   └── 3_Data_Explorer.py          # Intelligence search, filtering, and forensic CSV export
└── tests/
    └── test_detector.py            # Pytest suite covering all 20+ engine test cases
```

---

## Environment Setup & Launch Instructions

### Prerequisites

- Python 3.12+ (tested under Fedora Linux / WSL)
- SQLite 3 (standard library)

### Virtual Environment Setup

```bash
# Navigate to project directory
cd /home/montylr2722l/Projects/trace-fin

# Create virtual environment (if not already created)
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Running the Application

```bash
streamlit run app.py
```

Open your browser at **`http://localhost:8501`**.

The SQLite database is initialized automatically at `data/tracefin.db`. If the database is empty, synthetic demonstration records representing diverse threat categories will be seeded automatically.

### Running the Test Suite

```bash
# Run pytest with verbose test output
pytest -v tests/test_detector.py
```

The test suite validates:
1. Empty and whitespace-only inputs.
2. Legitimate bank advertisements.
3. Educational KYC explanations.
4. Normal utility payment reminders.
5. Suspicious bank account sales.
6. Combined account sale + KYC evasion.
7. Account rental / mule recruitment.
8. Urgency and secrecy combinations.
9. URL extraction and sanitization.
10. Email extraction.
11. Phone-like number extraction.
12. UPI payment identifier extraction.
13. Score bounds (0–100).
14. Risk-level score boundary mappings.
15. Explainable evidence presence.
16. Deterministic execution.
17. Contact details alone not causing false positives.
18. Backward-compatible database operations and column migrations.
19. Streamlit application and page imports.

---

## Detector Functional Contract

```python
def analyze_ad(text: str) -> dict[str, Any]:
    """
    Standard functional contract for TRACE//FIN analysis engine.

    Returns:
        dict:
            risk_score (int): 0 to 100.
            risk_level (str): 'Low' | 'Medium' | 'High' | 'Critical'.
            matched_categories (list[str]): Names of triggered categories.
            evidence (list[str]): Human-readable explanations of matched rules.
            urls (list[str]): Extracted URLs.
            emails (list[str]): Extracted email addresses.
            phone_numbers (list[str]): Extracted phone-like strings.
            payment_identifiers (list[str]): Extracted UPI / payment handles.
            review_required (bool): True if risk score >= 25.
            disclaimer (str): Neutral preliminary triage notice.
            review_recommendation (str): Specific triage recommendation.
            analysis_mode (str): 'rule_based'.
    """
```

---

## Future Roadmap

- **Phase 3:** Optical Character Recognition (OCR) for text embedded inside advertisement screenshots and posters.
- **Phase 4:** Cross-advertisement campaign discovery and entity relationship graph (clustering shared UPI handles, phone numbers, and phrases).
- **Phase 5:** Labelled benchmark dataset, machine learning classification baseline (e.g. transformer/BERT text classification), evaluation metrics (precision, recall, F1), and role-based access control.
