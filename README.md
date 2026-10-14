# TRACE//FIN

**Detect signals. Connect evidence. Prioritize investigations.**

AI-assisted financial cybercrime intelligence platform — Phase 1.

---

## Official Problem Statement

- **Problem ID:** SKIT002
- **Title:** AI & Cybercrime — AI-Based Detection of Suspicious Financial Advertisements

The platform identifies suspicious online advertisements and posts promoting the illicit sale or misuse of bank accounts, ATM cards, debit cards, credit cards, current accounts, savings accounts, or other financial access instruments.

The complete platform roadmap:
- Detection of financial account and card-sale language.
- Identification of high-risk claims (No KYC, guaranteed access, unauthorized account-use arrangements).
- Extraction of threat indicators (URLs, phone numbers, UPI/payment identifiers, advance payment demands).
- OCR extraction of text embedded within advertisement screenshots (Phase 3).
- Coordinated campaign and relationship discovery across shared identifiers (Phase 4).
- Decision-support prioritization for fraud and cybercrime investigators.

> **Investigator Principle:** A suspicious signal is **not** proof of a crime. Human review and verified due process remain essential parts of every workflow.

---

## Product Identity

- **Product Name:** TRACE//FIN
- **Product Category:** Financial Threat Intelligence
- **Tagline:** "Detect signals. Connect evidence. Prioritize investigations."
- **Aesthetic:** Modern, restrained cybersecurity intelligence console (dark navy `#0f1724`, slate panels, restrained cyan `#06b6d4` highlights).

---

## Phase 1 Capabilities & Boundaries

### Fully Implemented in Phase 1

| Component / Feature | Operational Status | Notes |
|---|---|---|
| **Investigator Console UI/UX** | ✅ Operational | Custom dark theme, consistent sidebar, responsive metrics, badges |
| **Threat Dashboard** | ✅ Operational | Database-derived metrics, Plotly charts (Risk, Activity, Categories), recent dossiers |
| **Ad Analysis Workflow** | ✅ Operational | Intake form, character count, validation, rule-based demo triage, DB save |
| **Case Management** | ✅ Operational | Filterable case list, status lifecycle transitions (Open/Reviewing/Escalated/Closed), DB persistence |
| **Intelligence Data Explorer** | ✅ Operational | Multi-field search, risk/status filtering, dossier inspection, forensic CSV export |
| **Persistent Storage** | ✅ Operational | SQLite (WAL mode) under `data/tracefin.db` with parameterized queries and JSON serialization |
| **Synthetic Demo Data** | ✅ Operational | 5 realistic synthetic examples (account sale, card sale, clean savings, awareness, ambiguous) seeded once |
| **Validation & Error Handling** | ✅ Operational | Input validation, empty states across all charts and tables, error feedback |

### Demo Boundaries (Planned for Future Phases)

| Future Capability | Current Phase 1 Status | Target Phase |
|---|---|---|
| **Trained ML Detection Model** | ⏳ Rule-based demo analyzer (`src/demo_analyzer.py`) | Phase 2 |
| **Labelled Training Dataset** | ⏳ Synthetic demonstration records only | Phase 2 |
| **OCR for Screenshot Text** | ⏳ Field marked "Not implemented" in case dossiers | Phase 3 |
| **Cross-Ad Network Graph** | ⏳ Field marked "Not implemented" in case dossiers | Phase 4 |
| **User Authentication / RBAC** | ⏳ Single investigator local session | Phase 5 |

> **Important:** All Phase 1 analysis results are explicitly marked with the `DEMO ANALYSIS` indicator. Scores reflect deterministic pattern matches and must not be represented as a probability of criminal activity.

---

## Project Structure

```
trace-fin/
├── app.py                          # Main dashboard entry point
├── config.py                       # Paths, constants, design tokens, risk levels
├── requirements.txt                # Production dependencies (streamlit, pandas, plotly)
├── README.md                       # Comprehensive platform documentation
├── .gitignore                      # Git exclusion rules
├── .streamlit/
│   └── config.toml                 # Streamlit dark theme & custom navigation config
├── assets/                         # Static assets directory
├── data/                           # SQLite database storage
│   └── tracefin.db                 # Auto-initialized SQLite database (WAL mode)
├── src/
│   ├── __init__.py
│   ├── database.py                 # SQLite CRUD, migration, and metrics layer
│   ├── demo_analyzer.py            # Rule-based demo pattern matcher & entity extractor
│   ├── sample_data.py              # Synthetic demo records (seeded once when DB is empty)
│   └── ui_components.py            # Reusable UI cards, badges, CSS, and record dossier
└── pages/
    ├── 1_Analyze_Advertisement.py  # Advertisement text intake and triage
    ├── 2_Investigation_Cases.py    # Case management & lifecycle status updates
    └── 3_Data_Explorer.py          # Intelligence search, filtering, and CSV export
```

---

## Environment Setup & Launch Instructions

### Prerequisites

- Python 3.12+ (tested under Fedora Linux / WSL)
- SQLite 3 (standard library)

### Virtual Environment Setup

```bash
# Navigate to the workspace
cd trace-fin

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Launching the Application

```bash
streamlit run app.py
```

The console will start at `http://localhost:8501`.

The SQLite database is created automatically at `data/tracefin.db` on first run. If the database is empty, 5 synthetic demo records will be seeded automatically.

---

## Database Architecture

- **Path:** `data/tracefin.db`
- **Engine:** SQLite with WAL mode (`PRAGMA journal_mode=WAL`)
- **Schema:**
  - `record_id`: Stable identifier (e.g. `TF-A1B2C3D4`)
  - `ad_text`: Raw advertisement / post content
  - `submitted_at`: ISO 8601 UTC timestamp
  - `analysis_mode`: Execution engine marker (`demo`)
  - `risk_score`: Quantitative risk score (0.0 – 100.0)
  - `risk_level`: Severity tier (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `MINIMAL`)
  - `matched_categories`: JSON array of triggered risk indicators
  - `evidence`: JSON object mapping categories to extracted evidence snippets
  - `urls`: JSON array of extracted URLs (with cleaned trailing punctuation)
  - `phone_numbers`: JSON array of extracted contact phone numbers
  - `payment_identifiers`: JSON array of extracted UPI / crypto payment handles
  - `review_required`: Integer boolean (1 if risk score >= 40, else 0)
  - `review_recommendation`: Human-readable investigator action recommendation
  - `investigation_status`: Operational status (`Open`, `Reviewing`, `Escalated`, `Closed`)
  - `is_synthetic`: 1 for seeded sample records, 0 for user submissions

---

## Future Integration Interface

In subsequent phases, the deterministic demo analyzer will be swapped with a trained machine learning pipeline. The platform isolates this integration via a single stable functional contract:

```python
def analyze_ad(text: str) -> dict:
    """
    Standardized detector contract for TRACE//FIN analysis engine.

    Args:
        text (str): Raw advertisement or message text.

    Returns:
        dict:
            risk_score (float): Computed risk score from 0.0 to 100.0.
            risk_level (str): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'MINIMAL'.
            matched_categories (list[str]): Triggered threat categories.
            evidence (dict[str, list[str]]): Category-to-snippets mapping.
            urls (list[str]): Extracted URLs.
            phone_numbers (list[str]): Extracted contact numbers.
            payment_identifiers (list[str]): Extracted payment identifiers.
            review_required (bool): Flag indicating human review is recommended.
            review_recommendation (str): Specific triage action for investigators.
            analysis_mode (str): Engine version or mode indicator.
    """
```

Because presentation, storage, and analysis logic are completely separated, replacing `src/demo_analyzer.py` with an ML model requires zero changes to the UI pages or database schema.

---

## Security & Privacy Considerations

- **Local Processing:** No advertisement text is transmitted to external cloud services or third-party APIs.
- **Data Protection:** Synthetic records use RFC-standard reserved domains (`example.com`) and fictional phone/account patterns. No actual credentials, payment secrets, or real personally identifiable information (PII) are stored.
- **SQL Injection Prevention:** All database operations strictly employ parameterized SQLite bindings (`?`).
