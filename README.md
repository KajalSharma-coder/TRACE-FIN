# TRACE//FIN

**Detect signals. Connect evidence. Prioritize investigations.**

AI-assisted financial cybercrime intelligence platform — Phase 3: Dataset-Driven ML Integration & Dual-Engine Intelligence.

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
- Supervised ML classification baseline using TF-IDF and Logistic Regression (**Phase 3**).
- Dual-engine threat triage comparing explainable heuristic rules with statistical ML (**Phase 3**).
- OCR extraction of text embedded within advertisement screenshots (**Phase 4**).
- Coordinated campaign and relationship discovery across shared identifiers (**Phase 4**).
- Decision-support prioritization for fraud and cybercrime investigators.

> **Investigator Mandate:** A suspicious signal is **not** proof of a crime. Human review and verified due process remain essential parts of every workflow. Automated scores are preliminary triage indicators, not definitive proof of illegal activity.

---

## Product Identity

- **Product Name:** TRACE//FIN
- **Product Category:** Financial Threat Intelligence
- **Tagline:** "Detect signals. Connect evidence. Prioritize investigations."
- **Aesthetic:** Modern, restrained cybersecurity intelligence console (dark navy `#0f1724`, slate panels, restrained cyan `#06b6d4` highlights).

---

## Phase 3: Dataset-Driven Machine Learning Baseline

Phase 3 introduces a reproducible text classification baseline built using scikit-learn (`TF-IDF + Logistic Regression`) integrated directly alongside Phase 2's explainable heuristic detection engine.

### 1. Dataset Inspection & Governance

The platform inspects two local datasets under `data/`:

#### A. Primary Training Dataset: `data/back.dataset.csv`
- **Total Samples:** 500 records
- **Schema:** `['ID_No', 'Account_Holder_Name', 'Bank_Account_No', 'IFSC_Code', 'Advertisement_Text', 'Risk_Label']`
- **Missing Values:** 0
- **Class Distribution:**
  - `High Risk`: 253 records (50.6%) — Positive Class (1)
  - `Safe`: 247 records (49.4%) — Negative Class (0)
- **Strict Data Governance (Zero PII Usage):** Identifier columns (`ID_No`, `Account_Holder_Name`, `Bank_Account_No`, `IFSC_Code`) are **strictly excluded** from model training. No banking credentials, account numbers, or personal names are ever printed, logged, or utilized as predictive features.
- **Token Normalization:** During preprocessing, embedded account numbers, IFSC codes, UPI handles, and amounts are replaced with generic semantic tokens (`<ACCOUNT_NUM>`, `<IFSC_CODE>`, `<UPI_HANDLE>`, `<RENTAL_AMOUNT>`). This ensures the vectorizer learns financial crime terminology rather than memorizing synthetic account numbers.

#### B. Secondary Dataset: `data/cleaned_spam_dataset.csv`
- **Total Samples:** 5,572 records (`ham`: 4,825, `spam`: 747)
- **Schema:** `['label', 'message']`
- **Task Isolation:** This dataset represents generic SMS spam (promotions, sweepstakes, dating solicitations). It is **not** merged into the primary financial ad training data, preventing label distortion and cross-domain semantic contamination.

---

### 2. ML Baseline Architecture & Evaluation

- **Pipeline:** `sklearn.pipeline.Pipeline`
  1. `TfidfVectorizer`: Sublinear term-frequency scaling, unigrams & bigrams `(1, 2)`, English stop words removal, `min_df=2`, `max_df=0.98`.
  2. `LogisticRegression`: Fixed seed `random_state=42`, `class_weight="balanced"`, `C=1.0`, `solver="lbfgs"`.
- **Validation Strategy:** Stratified 80/20 train/test split with seed 42.
  - Training Set: 400 records (202 High Risk, 198 Safe)
  - Held-out Test Set: 100 records (51 High Risk, 49 Safe)
- **Leakage Prevention:** The vectorizer and all vocabulary statistics are fitted **strictly on the training split**.

#### Performance on Held-Out Test Split (100 Samples)

| Metric | Safe (Class 0) | High Risk (Class 1) | Macro Average |
|---|---|---|---|
| **Precision** | 1.0000 | 1.0000 | 1.0000 |
| **Recall** | 1.0000 | 1.0000 | 1.0000 |
| **F1-Score** | 1.0000 | 1.0000 | 1.0000 |
| **Support** | 49 | 51 | 100 |
| **Overall Accuracy** | — | — | **100.00%** |

#### Confusion Matrix
```
                      Predicted Safe    Predicted High Risk
Actual Safe (0)             49                    0
Actual High Risk (1)         0                   51
```

#### Top Influential Vocabulary Signals (Logistic Regression Coefficients)
- **High-Risk Signals (+):** `rent`, `rent bank`, `bank account`, `rental_amount`, `send details`, `transaction advance`, `hawala`, `selling fully kyc`
- **Safe Signals (-):** `refund`, `refund account`, `vendor`, `vendor payment`, `payment details`, `donation`, `donation accepted`, `salary account`

---

### 3. Honest Scientific Limitations

1. **Synthetic Template Overfitting:** Inspection of `back.dataset.csv` revealed that all 500 samples are permutations of 4 syntactic templates for High Risk and 4 templates for Safe. The 100% test score reflects memorization within this narrow synthetic distribution.
2. **Real-World Generalization Gap:** Novel real-world criminal phrasing outside these 4 templates (e.g. *"Work from home: receive transfers into your personal account and keep 10% commission"*) can trigger false negatives in the ML model, while being caught immediately by Phase 2's domain heuristics.
3. **Non-Calibrated Probabilities:** Logistic regression decision probabilities reflect geometric distance to the separating hyperplane on the synthetic dataset, **not** real-world calibrated crime likelihoods.
4. **Complementary Deployment:** The ML model is deployed as an advisory companion alongside the Phase 2 explainable rule engine, never as an unverified single point of failure.

---

### 4. Dual-Engine Intelligence Architecture

TRACE//FIN executes **Dual-Engine Triage** on every advertisement:

1. **Explainable Rule-Based Engine (Phase 2):**
   - 5 modular threat categories: Account/Card Sale, KYC Evasion, Account Rental / Mule Recruitment, Suspicious Solicitation, Urgency & Secrecy.
   - Deterministic 0–100 score mapped to standardized tiers (`Low`, `Medium`, `High`, `Critical`).
   - Contextual false-positive mitigation for educational/regulatory guidelines.
2. **Supervised ML Baseline (Phase 3):**
   - Independent TF-IDF + Logistic Regression classification.
   - Decision score and active vocabulary signal extraction.
3. **Consensus & Divergence Evaluation:**
   - **Consensus Threat:** Both engines flag high risk → Highest triage priority.
   - **Consensus Safe:** Both engines agree content is benign → Routine low priority.
   - **Rule Alert (ML Divergence):** Heuristic flags threat but ML predicts Safe → Warns investigator that novel phrasing outside the synthetic training distribution is present.
   - **ML Anomaly Alert:** ML flags high score while rules do not fire → Recommends investigator review top token signals for spurious correlation.

---

## Project Structure

```
trace-fin/
├── app.py                         # Threat Intelligence Dashboard (Overview, KPIs, Charts)
├── config.py                      # Design tokens, paths, standardized risk tiers
├── requirements.txt               # Dependencies (Streamlit, Pandas, Plotly, Scikit-learn, Pytest)
├── README.md                      # Comprehensive documentation
├── data/
│   ├── back.dataset.csv           # Primary financial advertisement dataset (500 records)
│   ├── cleaned_spam_dataset.csv   # General SMS spam dataset (isolated)
│   └── tracefin.db                # SQLite persistent storage (WAL mode, automated schema migration)
├── models/
│   ├── financial_ad_classifier.joblib  # Trained scikit-learn TF-IDF + LogReg pipeline
│   └── model_metrics.json         # Persisted evaluation metrics and feature weights
├── pages/
│   ├── 1_Analyze_Advertisement.py # Dual-Engine Intake & Analysis (Heuristics + ML Diagnostics)
│   ├── 2_Investigation_Cases.py   # Case Management, Filter, Status Workflow & Details
│   └── 3_Data_Explorer.py         # Tabular Browser, Multi-indicator Filter, Forensic CSV Export
├── scripts/
│   └── train_model.py             # Reproducible ML training and benchmarking CLI
├── src/
│   ├── database.py                # Isolated SQLite persistence layer (idempotent migrations)
│   ├── detector.py                # Explainable rule-based heuristic detection engine (Phase 2)
│   ├── ml_model.py                # ML pipeline, preprocessing, training, inference & consensus
│   ├── sample_data.py             # Synthetic demonstration records
│   └── ui_components.py           # Reusable dark cybersecurity console UI components
└── tests/
    ├── test_detector.py           # Phase 2 test suite (20 deterministic heuristic tests)
    └── test_ml.py                 # Phase 3 test suite (15 dataset, ML, inference, consensus tests)
```

---

## Installation & Setup

### Environment Requirements
- Python 3.12+ (tested on Python 3.14 under Linux/WSL).
- Virtual environment recommended.

```bash
# Clone the repository
git clone <repo-url>
cd trace-fin

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Model Training CLI

To retrain the ML baseline and generate fresh artifacts under `models/`:

```bash
python scripts/train_model.py
```

### Running the Application

```bash
streamlit run app.py
```

Open your browser at **`http://localhost:8501`**.

The SQLite database initializes automatically at `data/tracefin.db`. Existing records are safely migrated without data loss.

### Running the Full Test Suite

```bash
# Run all 35 tests (Detector + ML)
pytest -v tests/
```

Test coverage includes:
- **Heuristics:** Empty inputs, benign banking, educational KYC notices, account sales, KYC bypass, mule recruitment, urgency combinations, indicator extractions (URLs, emails, phones, UPIs), score bounds.
- **Machine Learning:** Token preprocessing, dataset integrity, spam dataset isolation, PII column exclusion, reproducible pipeline training, positive and negative class inference, missing model fallback, consensus/divergence logic, and database persistence.

---

## Functional Contracts

### 1. Rule-Based Detector (`src/detector.py`)
```python
def analyze_ad(text: str) -> dict[str, Any]:
    """
    Returns:
        risk_score (int): 0 to 100.
        risk_level (str): 'Low' | 'Medium' | 'High' | 'Critical'.
        matched_categories (list[str]): Triggered threat categories.
        evidence (list[str]): Explainable evidence strings.
        urls, emails, phone_numbers, payment_identifiers (list[str]).
        review_required (bool): True if risk_score >= 25.
        disclaimer (str): Preliminary triage notice.
        analysis_mode (str): 'rule_based'.
    """
```

### 2. Machine Learning Classifier (`src/ml_model.py`)
```python
def predict_ad_ml(text: str) -> dict[str, Any]:
    """
    Returns:
        available (bool): True if model artifact loaded and text analyzed.
        risk_label (str): 'High Risk' | 'Safe' | None.
        prediction (int): 1 (High Risk) or 0 (Safe).
        high_risk_score (float): Decision probability for positive class (0.0 to 1.0).
        confidence (float): Classification confidence (0.5 to 1.0).
        confidence_pct (float): Confidence percentage.
        model_version (str): e.g. 'tfidf-logreg-v1.0'.
        top_signals (list[dict]): Active vocabulary tokens and their logistic weights.
        disclaimer (str): Scientific interpretability notice.
    """
```

---

## Future Roadmap

- **Phase 4:** Optical Character Recognition (OCR) for text embedded inside advertisement screenshots and posters.
- **Phase 4:** Cross-advertisement campaign discovery and entity relationship graph (clustering shared UPI handles, phone numbers, and phrases).
- **Phase 5:** Pre-trained transformer/BERT fine-tuning on expanded naturalistic financial crime corpora, and role-based access control.
