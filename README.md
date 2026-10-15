# TRACE//FIN

**Detect signals. Connect evidence. Prioritize investigations.**

AI-assisted financial cybercrime intelligence platform — Phase 5: Multi-Format Intake, Secure URL Triage & Hardened Verification.

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
- Batch CSV advertisement triage with formula-injection-safe exports (**Phase 4**).
- Fine-tuned Hugging Face DistilBERT sequence classifier (**Phase 4**).
- Secure URL analysis with SSRF mitigation and domain threat indicators (**Phase 5**).
- In-memory document text extraction for PDF and DOCX files (**Phase 5**).
- Unified multi-format triage console with editable human review step (**Phase 5**).
- Hardened security and regression testing suite (**Phase 5**).
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

### AI Integration and API Credentials

The documented TRACE//FIN requirements do **not** require OpenAI or another hosted inference API. Advertisement analysis uses the local scikit-learn artifact (`models/financial_ad_classifier.joblib`), the explainable rule engine, and—when its fine-tuned artifacts are installed—the local DistilBERT model under `models/hf_financial_ad_classifier/`. Inference does not need a provider API key and does not fall back to fabricated or remote responses when local models are unavailable; the application reports the unavailable engine and continues with the remaining evidence sources.

Training DistilBERT downloads the public base model from Hugging Face Hub; inference loads the saved project-local tokenizer and weights. `HF_TOKEN` is not currently consumed by the application. The `DATABASE_URL` value shown in `.env.example` is for database access only, not AI inference. Keep local secrets in the ignored `.env` or Streamlit secrets file; do not add real keys to source code or examples.

The fine-tuned `model.safetensors` checkpoint is 256 MB and is excluded from ordinary Git commits because it exceeds GitHub's 100 MB per-file limit. It remains local in this workspace; a fresh clone must obtain/retrain that checkpoint separately before DistilBERT inference is available. The app continues to report the transformer as unavailable and uses its other analysis engines when weights are absent.

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
- **Validation Strategy:** The current training and comparison scripts use a template-grouped, class-stratified train/validation/test split with seed 42. This dataset yields 254 train, 114 validation, and 132 test rows, while keeping normalized template groups disjoint.
- **Leakage Prevention:** Vectorizer vocabulary and classifier weights are fitted on training rows only; validation is used for candidate selection and test rows are evaluated after selection.

#### Historical Row-Random Artifact Metrics (Not a Generalization Estimate)

The current checked-in `models/model_metrics.json` was generated before template-grouped splitting and reports a random row split. Its perfect score is contaminated by shared templates across partitions and must not be used as evidence of real-world performance. Running the current grouped benchmark is described below.

#### Template-Grouped Candidate Comparison (Current Dataset)

The experimental run used one shared split (train 254; validation 114; held-out test 132), trained each candidate for one epoch with truncation at 128 tokens, selected by validation macro-F1 with High Risk recall as tie-breaker, and evaluated every candidate on test only after selection. Candidate weights were kept in `/tmp` and existing model files were not replaced. The independent unit count is just 8 templates, so the row counts do not represent 132 independent text patterns.

| Candidate | Validation Accuracy / Macro F1 | Test Accuracy | High Risk P / R / F1 | FNR | Test confusion matrix (actual rows, predicted columns: Safe / High Risk) |
|---|---:|---:|---:|---:|---|
| TF-IDF + Logistic Regression | 0.4474 / 0.3091 | 0.0000 | 0 / 0 / 0 | 1.0000 | `[[0, 66], [66, 0]]` |
| Fresh DistilBERT scam-ad fine-tune | 1.0000 / 1.0000 | 1.0000 | 1 / 1 / 1 | 0.0000 | `[[66, 0], [0, 66]]` |
| ProsusAI/FinBERT with a new scam-ad classifier head | 1.0000 / 1.0000 | 1.0000 | 1 / 1 / 1 | 0.0000 | `[[66, 0], [0, 66]]` |

Validation selected fresh DistilBERT by stable candidate order after the candidates tied on macro-F1 and High Risk recall. ProsusAI/FinBERT was used only as a financial-language encoder with its sentiment classifier head replaced; its original positive/negative/neutral classes are not scam labels. The benchmark does not establish that either transformer generalizes beyond these synthetic templates. The current DistilBERT artifact has no training-split manifest, so its held-out status cannot be verified and it was excluded from candidate selection. The benchmark command is `python scripts/benchmark_ad_models.py --finbert /path/to/ProsusAI-finbert --epochs 1 --max-length 128`.

The ProsusAI model card describes financial sentiment classes, not scam-ad classes: [ProsusAI/finbert model card](https://huggingface.co/ProsusAI/finbert).

The previous table below records the old artifact's random-row test results, not the grouped comparison.

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

1. **Synthetic Template Overfitting:** After normalizing holder names in template fingerprints, `back.dataset.csv` contains only 8 distinct templates (4 per class). Existing artifact evaluation uses the earlier split implementation and does not establish real-world generalization.
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

### Interactive advertisement evidence graph (`pages/1_Analyze_Advertisement.py`)

After an advertisement is analyzed, TRACE//FIN builds a structured evidence graph from the existing rule matches, extracted identifiers, URL model results, OCR source, and saved records. Plotly renders the graph as interactive 3D circles with curved, labelled edges; investigators can rotate, zoom, pan, and click a node to inspect its redacted value, source, reason, and available model score. Category filters and a high-risk-only toggle update the graph. Risk score and advertisement classification continue to come from `run_unified_analysis`; generic URL phishing predictions remain separate. Shared phone or URL indicators appear only on exact matches in another saved non-synthetic record. Bank-name nodes indicate a text mention, not affiliation. The current OCR pipeline does not verify fake logos or visual authenticity, and no domain reputation feed or calibrated confidence is available.

The visualization uses the declared `streamlit-plotly-events` dependency for node click details and Plotly's built-in 3D camera controls. Sensitive values such as account/card numbers, OTPs, CVVs, PINs, passwords, and URL tokens are redacted. Phone numbers are partially masked.

---

## Phase 4: Multi-Modal, Batch Processing & DistilBERT Fine-Tuning

### Feature A: Image & Screenshot OCR Analysis (`pages/4_Image_Analysis.py`)
- Upload JPG, JPEG, PNG, or WEBP screenshots with size (max 10MB) and dimension (50-8000px) validation.
- Extracts advertisement text locally using EasyOCR with Tesseract fallback and confidence scoring. EasyOCR obtains its official recognition weights on first use if they are not cached; uploaded images remain local.
- Displays extracted text in an editable text area before analysis, allowing human investigators to correct OCR transcription errors.
- Runs text through Rule Heuristics, TF-IDF Classifier, and DistilBERT with separate indicators.
- **Privacy Assurance:** Images are processed in-memory and are **never** persisted to disk or sent to external cloud APIs.

### Supplied URL phishing model
- `models/url_phishing_classifier.onnx` is the supplied `pirocheto/phishing-url-detection` ONNX artifact. It classifies generic URL phishing likelihood, not financial advertisements. TRACE//FIN surfaces its output as supplementary evidence; it does not modify the detector's score, final label, or recommendation.
- The archive also contained a pickle model. TRACE//FIN does not load or execute that pickle.
- The upstream model card's evaluation values are not reproduced as TRACE//FIN measurements; this repository does not include the source evaluation dataset or split needed to independently verify them.

### Optional MCP browser analysis

The local MCP server exposes `inspect_financial_url` over stdio. It uses the existing URL syntax checks, DNS and redirect SSRF protections, response limits, ONNX phishing URL classifier, and unified financial-ad pipeline. URL phishing classification and advertisement risk are returned as separate fields. The optional Playwright step renders only escaped, extracted text in an inert local page; JavaScript is disabled and all browser network requests are blocked. If Playwright or its browser is unavailable, safe extracted text and the existing pipeline are still returned.

From Windows PowerShell, create an isolated Python 3.12 environment, install the declared requirements, and install the Chromium runtime once:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m playwright install chromium
```

Run the Streamlit application independently:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Run the MCP server from the project directory (stdio, intended to be launched by a local MCP client):

```powershell
.\.venv\Scripts\python.exe mcp_server.py
```

For an MCP client that accepts a JSON stdio server configuration, add:

```json
{
  "mcpServers": {
    "tracefin": {
      "command": "C:/path/to/trace-fin/.venv/Scripts/python.exe",
      "args": ["C:/path/to/trace-fin/mcp_server.py"],
      "cwd": "C:/path/to/trace-fin"
    }
  }
}
```

Use an absolute Windows path for `command`, `cwd`, and `args`. The server does not expose a network listener. Treat returned webpage text as untrusted evidence; this integration does not execute page instructions, submit forms, or collect credentials. The fetcher checks all DNS answers, pins the HTTP connection to one checked public IP, repeats that process for every redirect, disables proxy inheritance, validates TLS against the original hostname, and enforces its timeout, redirect, and response-size bounds. The browser renders only escaped extracted text in an inert local document, with JavaScript disabled and all requests blocked.

### Sign-in persistence across refreshes

The login persists for 30 days using an opaque random browser cookie. SQLite stores only a SHA-256 hash of the token; signing out revokes it. The cookie is `SameSite=Strict` and `Secure` by default. Keep `TRACEFIN_AUTH_COOKIE_SECURE=true` on HTTPS deployments. For plain HTTP development on a non-localhost hostname, set it to `false` in the local environment (never use that setting on a public deployment). The cookie component is JavaScript-readable, so protect the application against cross-site scripting and use HTTPS in deployment.

### Feature B: Batch CSV Advertisement Analysis (`pages/5_Batch_CSV_Analysis.py`)
- Upload CSV datasets up to 5,000 rows and 50MB. Auto-detects UTF-8, Latin-1, and CP1252 encodings.
- Column mapping configuration: select advertisement text column and optional ground-truth label column.
- Live progress indicator during batch execution across all triage engines.
- **Spreadsheet Formula Injection Defense:** Neutralizes dangerous prefixes (`=`, `+`, `-`, `@`, `\t`, `\r`) with tab-character prepending on exported CSV files.

### Feature C & D: Hugging Face DistilBERT Fine-Tuning (`src/hf_model.py`, `scripts/train_hf_model.py`)
- Base model: `distilbert/distilbert-base-uncased` with AutoTokenizer and AutoModelForSequenceClassification.
- **Strict PII Exclusion:** Never uses `ID_No`, `Account_Holder_Name`, `Bank_Account_No`, or `IFSC_Code`.
- **Grouped Template Splitting:** Groups syntactic template fingerprints (first 35 characters) into isolated train/val/test partitions to prevent near-identical phrasing from leaking across evaluation splits.
- Holder names embedded in ad text are normalized for grouping, along with account numbers and IFSC codes; each class is stratified across partitions when enough independent templates exist. Current data has only eight normalized templates (four per class), so metrics remain highly template-dependent.
- **CLI Training Script:** Configurable epochs, batch size, learning rate, random seed, device selection (auto-detects CUDA/CPU), and held-out test evaluation.
- Backs up previous model directories before saving weights, tokenizer files, and metadata to `models/hf_financial_ad_classifier/`.

The existing local artifact metadata records a 180-example holdout with accuracy 0.7222, high-risk precision 1.0000, recall 0.5968, and confusion matrix `[[56, 0], [50, 74]]` (rows Safe/High Risk, columns predicted Safe/High Risk). Its recorded validation split contained only Safe examples (25/25); that accuracy is not a meaningful two-class validation result. These are historical artifact metrics from the earlier split implementation, not metrics from a retrained model. No retraining was performed during the audit.

---

## Phase 5: Multi-Format Intake, Secure URL Analysis & Hardened Verification

### Feature A: Secure URL Analysis & SSRF Mitigation (`src/url_fetcher.py`)
- **Strict Syntax & Scheme Control:** Restricts schemes strictly to `http://` and `https://`. Blocks embedded credentials (`user:pass@host`), malformed hostnames, and arbitrary URI protocols (`file://`, `ftp://`, `javascript:`, `data:`).
- **SSRF Network Protection:**
  - Allows only globally routable IPs, blocking loopback, private, link-local, shared, reserved, multicast, unspecified, IPv4-mapped internal IPv6, and cloud metadata targets. Local/internal host suffixes are also rejected.
  - Resolves and validates every DNS answer, then pins the request URL to one checked IP. HTTPS retains the original hostname for SNI and certificate verification. Proxy environment variables are disabled to prevent indirect destination resolution.
- **Manual Redirect Chain Validation:** Disables automatic HTTP client redirect following. Inspects and re-validates, then pins, every redirect destination (up to 3 hops max).
- **Resource Limits & Safe Parsing:** Enforces strict 5.0-second network timeouts and 2 MB streamed payload caps. Strips `<script>`, `<style>`, `<svg>`, `<nav>`, and `<form>` tags using BeautifulSoup without client-side script execution.
- **Explainable Domain Threat Indicators:** Detects IP-literal hostnames, excessive subdomain nesting, high hyphen counts, and suspicious financial phishing keywords (`kyc`, `instant`, `cashout`, `mule`, `hawala`, `loan`).

### Feature B: Document Ingestion for PDF & Word (`src/document_extractor.py`)
- **PDF Extraction (`pypdf`):**
  - Magic header validation (`%PDF-`), 10 MB file size limit, and 30-page processing cap.
  - Page-by-page text extraction with encrypted/password-protected document handling.
  - Scanned PDF detection: explicitly warns investigators when a PDF contains no extractable text.
- **DOCX Extraction (`python-docx`):**
  - ZIP container signature validation (`PK\x03\x04`), 10 MB upload cap, and 50 MB decompressed ratio limit protecting against ZIP bomb / XML expansion attacks.
  - Extracts text from both body paragraphs and structured table cells.
- **Zero Ingestion Leakage:** All documents are parsed in-memory from stream buffers. No temporary files are written to disk.

### Feature C: Unified Multi-Format Triage Console (`pages/1_Analyze_Advertisement.py`)
- 5 Intake Modes in dedicated investigator tabs:
  1. `📝 Raw Text`
  2. `🌐 Website URL` (Live Safe Fetch or Domain Syntax Analysis)
  3. `🖼️ Screenshot / Image` (EasyOCR / Tesseract local OCR preview & transcription)
  4. `📄 PDF Document` (Page count, metadata & extraction)
  5. `📑 Word Document (DOCX)` (Paragraph & table extraction)
- **Mandatory Human Review Step:** Extracted content is presented in an editable text area alongside source metadata, character/word counters, and extraction warnings. The investigator retains full authority to review, sanitize, or edit the content before initiating detection.
- **Triple-Engine Triage:** Running analysis triggers Heuristic Rules + TF-IDF Classifier + Hugging Face DistilBERT simultaneously, generating consensus scoring and explainable indicator breakdowns.

### Feature D: Hardened Security & Regression Suite (`tests/test_security.py`, `tests/test_url.py`, `tests/test_docs.py`, `tests/test_database.py`)
- Automated regression suite: latest repository verification collected 154 tests; 153 passed and 1 was skipped.
- Security test matrix explicitly validating SSRF defense boundaries, CSV formula injection vectors, PII exclusion from model pipelines, SQL injection resistance, and database record persistence.

### Feature E: Enterprise Storage — Neon-Hosted PostgreSQL Integration (`src/database.py`, `scripts/migrate_sqlite_to_postgres.py`)
- **Serverless PostgreSQL Primary:** Fully integrated Neon serverless PostgreSQL via SQLAlchemy 2.0 Core and Psycopg 3 (`postgresql+psycopg://`).
- **Connection Resilience:** Configured with `pool_pre_ping=True`, `pool_size=5`, `max_overflow=10`, and `pool_recycle=1800` to transparently survive Neon compute autosuspend/wake cycles without connection errors.
- **Graceful Local Fallback:** When `DATABASE_URL` is not configured, the platform transparently falls back to local SQLite in WAL mode (`data/tracefin.db`), guaranteeing complete offline functionality.
- **Strict Credential Security:** URL masking (`mask_db_url()`) redacts database passwords from UI diagnostics, logs, error messages, and documentation. Credentials resolve securely via environment variables (`DATABASE_URL`), Streamlit secrets (`st.secrets["DATABASE_URL"]`), or local `.env` files.
- **Idempotent Migration Utility:** Standalone CLI tool (`scripts/migrate_sqlite_to_postgres.py`) to safely transfer legacy SQLite records into Neon PostgreSQL with `--dry-run` transaction rollback support and duplicate skipping.

---

## Project Structure

```
trace-fin/
├── app.py                             # Threat Intelligence Dashboard (Overview, KPIs, Charts)
├── config.py                          # Design tokens, paths, standardized risk tiers (v0.5.0-phase5)
├── requirements.txt                   # Dependencies (Streamlit, SQLAlchemy, Psycopg, Torch, etc.)
├── README.md                          # Comprehensive architecture and operations documentation
├── .env.example                       # Sanitized template for environment variables
├── .streamlit/
│   └── secrets.toml.example           # Sanitized template for Streamlit secrets
├── data/
│   ├── back.dataset.csv               # Primary financial advertisement dataset (500 records)
│   ├── cleaned_spam_dataset.csv       # General SMS spam dataset (isolated)
│   └── tracefin.db                    # SQLite persistent storage (WAL mode, offline fallback)
├── models/
│   ├── financial_ad_classifier.joblib # Trained scikit-learn TF-IDF + LogReg pipeline
│   ├── model_metrics.json             # Persisted TF-IDF evaluation metrics and feature weights
│   └── hf_financial_ad_classifier/    # Fine-tuned DistilBERT config/tokenizer; large weights excluded (see note)
├── pages/
│   ├── 1_Analyze_Advertisement.py     # Unified Multi-Format Console (Text, URL, Image, PDF, DOCX)
│   ├── 2_Investigation_Cases.py       # Case Management, Filter, Status Workflow & Details
│   ├── 3_Data_Explorer.py             # Tabular Browser, Multi-indicator Filter, Forensic CSV Export
│   ├── 4_Image_Analysis.py            # Screenshot & Image OCR Intake, Text Correction & Triage
│   └── 5_Batch_CSV_Analysis.py        # Bulk CSV Intake, Column Mapping & Formula-Safe Export
├── scripts/
│   ├── train_model.py                 # Reproducible TF-IDF + LogReg training CLI
│   ├── train_hf_model.py              # Hugging Face DistilBERT fine-tuning & evaluation CLI
│   └── migrate_sqlite_to_postgres.py  # Idempotent SQLite to Neon PostgreSQL data migration utility
├── src/
│   ├── database.py                    # SQLAlchemy 2.0 persistence layer (Neon PostgreSQL primary, SQLite WAL fallback)
│   ├── detector.py                    # Explainable rule-based heuristic detection engine (Phase 2)
│   ├── ml_model.py                    # TF-IDF + LogReg ML pipeline, training & consensus (Phase 3)
│   ├── hf_model.py                    # DistilBERT dataset grouping, training & inference (Phase 4)
│   ├── ocr_engine.py                  # EasyOCR/Tesseract extraction and image validation (Phase 4)
│   ├── url_model.py                   # Optional ONNX phishing URL classifier (supplementary only)
│   ├── csv_analyzer.py                # Batch CSV validation, triage engine & formula sanitizer (Phase 4)
│   ├── url_fetcher.py                 # Secure URL validator, SSRF mitigation & HTML parser (Phase 5)
│   ├── document_extractor.py          # PDF & DOCX in-memory text extraction & safety caps (Phase 5)
│   ├── sample_data.py                 # Synthetic demonstration records
│   └── ui_components.py               # Reusable dark cybersecurity console UI components & connection badges
└── tests/
    ├── test_detector.py               # Phase 2 test suite (20 heuristic tests)
    ├── test_ml.py                     # Phase 3 test suite (15 dataset, ML & consensus tests)
    ├── test_ocr.py                    # Phase 4 test suite (9 image validation & OCR tests)
    ├── test_csv.py                    # Phase 4 test suite (7 CSV validation & sanitization tests)
    ├── test_hf.py                     # Phase 4 test suite (6 DistilBERT dependency & dataset tests)
    ├── test_url.py                    # Phase 5 test suite (17 URL syntax, SSRF & redirect tests)
    ├── test_docs.py                   # Phase 5 test suite (7 PDF & DOCX safety extraction tests)
    ├── test_security.py               # Phase 5 security matrix (5 SSRF, CSV injection, PII tests)
    ├── test_risk_synthesis.py         # Unified risk synthesis & bounded scoring
    ├── test_input_methods_audit.py    # Cross-input triage consistency & validation (19 tests)
    ├── test_ui_sync.py                # Streamlit session-state synchronization suite (11 tests)
    └── test_database.py               # Database engine, pooling, migration & SQL injection (14 tests)
```

---

## Installation & Setup

### Environment Requirements
- Python 3.12+ (tested on Python 3.14 under Linux/WSL).
- EasyOCR defaults to English. Its official recognition weights may be downloaded into the local cache on first use. Set `TRACEFIN_EASYOCR_LANGUAGES=en,hi` for additional supported languages.
- Set `TRACEFIN_OCR_ENGINE=tesseract` to prefer Tesseract, `easyocr` to prefer EasyOCR, or leave it unset for EasyOCR-first with Tesseract fallback.
- Optional system Tesseract fallback:
  - Fedora: `sudo dnf install tesseract`
  - Ubuntu/Debian: `sudo apt-get install tesseract-ocr`
  - macOS: `brew install tesseract`

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

### Model Training CLIs

#### 1. Retrain TF-IDF Baseline (Phase 3)
```bash
python scripts/train_model.py
```

#### 2. Fine-Tune DistilBERT Transformer (Phase 4)
```bash
python scripts/train_hf_model.py --epochs 3 --batch-size 8 --lr 2e-5
```

#### 3. Train and validation-select the sourced scam-message candidate
```bash
python scripts/train_expanded_model.py
```
This keeps `data/back.dataset.csv` and the existing model artifact unchanged,
trains a TF-IDF + Logistic Regression candidate using sourced training data,
and selects it only when its grouped validation macro-F1 (then High Risk recall)
improves on both the manually labelled scam-message corpus and an ad-only
training reference. The held-out test partition is evaluated only after
selection. Read [`data/external/README.md`](data/external/README.md) for dataset
attribution and scope limitations. The reported external test results cover
manually labeled scam messages, not representative financial advertisements.

### Database Configuration & Persistence

TRACE//FIN uses **Neon Serverless PostgreSQL** as its primary persistent database, with an automatic, zero-configuration local fallback to **SQLite (WAL mode)** at `data/tracefin.db` when no remote connection string is configured.

#### 1. Configuring Neon PostgreSQL Credentials

Set the connection string in either of the following supported locations (never commit real credentials):

- **Streamlit Secrets (Local or Community Cloud):**
  Create or edit `.streamlit/secrets.toml` (ignored by git; see template `.streamlit/secrets.toml.example`):
  ```toml
  DATABASE_URL = "postgresql://USER:PASSWORD@HOST:5432/DATABASE?sslmode=require"
  ```

- **Environment Variable (Local `.env` or Container / Cloud Deployments):**
  Create or edit `.env` (ignored by git; see template `.env.example`):
  ```bash
  DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/DATABASE?sslmode=require
  ```

- **Platform Deployment Settings:**
  - **Streamlit Community Cloud:** App Dashboard → Settings → Secrets → Paste `DATABASE_URL = "..."`.
  - **Render / Railway / Fly.io / Docker:** Add an Environment Variable named `DATABASE_URL` with your connection string.

#### 2. Migrating Legacy SQLite Data to Neon PostgreSQL

An idempotent migration CLI is provided to safely migrate existing records from `data/tracefin.db` to Neon PostgreSQL:

```bash
# Preview records to be migrated without modifying the target database (dry run)
python scripts/migrate_sqlite_to_postgres.py --dry-run

# Execute live migration (idempotent, skips duplicates, preserves existing records)
python scripts/migrate_sqlite_to_postgres.py
```

### Running the Application

```bash
streamlit run app.py
```

Open your browser at **`http://localhost:8501`**.

The root page is a public TRACE//FIN overview. **Sign in** and **Enter workspace** open the existing local login flow; after authentication the app opens the protected dashboard. The public dashboard preview uses aggregate saved, non-synthetic data when available. With no saved analyses, its example metrics are explicitly marked illustrative and are never persisted. Logging out returns to the public overview.

Create a local account on first use. TRACE//FIN stores an Argon2id password hash in the `local_users` table in the SQLite database at `data/tracefin.db`; signup establishes a session immediately. Use **Log out** in the sidebar to clear the Streamlit session. There is no default account and no external identity provider is required.

Local authentication is intended for local/demo deployments. Accounts currently share the existing analysis records and case store; this is not multi-user data isolation. Before public production deployment, add a managed identity provider, HTTPS and hardened session controls, account recovery and rate limiting, and tenant ownership/filtering for persisted records and exports. Restrict OS access to the local SQLite file.

The analysis database schema initializes idempotently on startup. The local account table is stored in SQLite independently of any configured analysis database, so local sign-in does not depend on a live external database.

### Running the Full Test Suite

```bash
# Run the complete automated test suite
pytest -v
```

By default, test execution runs in offline isolation using an in-memory/isolated SQLite engine. To run the optional external PostgreSQL integration test, specify `TEST_DATABASE_URL`:

```bash
TEST_DATABASE_URL="postgresql://USER:PASSWORD@HOST:5432/DATABASE?sslmode=require" pytest tests/test_database.py -k test_neon_live_connection_if_configured
```

#### Test Suite Coverage (Latest run: 153 passed, 1 skipped)

| Test Module | Scope & Coverage |
|---|---|
| `tests/test_detector.py` | Rule-based heuristic detection, KYC bypass, mule solicitations, score bounding, contact indicator parsing |
| `tests/test_ml.py` | TF-IDF + LogReg pipeline, PII exclusion, dataset distribution, consensus triage & divergence alerts |
| `tests/test_ocr.py` | Image format validation (JPEG/PNG/WEBP), corruption, bounds checks, Tesseract availability |
| `tests/test_csv.py` | Batch CSV parsing, multi-encoding support, spreadsheet formula injection neutralization |
| `tests/test_hf.py` | DistilBERT transformer dependency checks, grouped template splitting, inference contracts |
| `tests/test_url.py` | Scheme validation, SSRF boundary matrix (private/loopback/cloud metadata), DNS rebinding, HTML triage |
| `tests/test_docs.py` | In-memory PDF header validation, scanned PDF alerts, DOCX tables, ZIP bomb expansion ratio guards |
| `tests/test_security.py` | SSRF attack vectors, CSV formula evasion payloads, PII omission guarantees, database integrity |
| `tests/test_risk_synthesis.py` | Unified 0-100 bounded scoring, rule-matching accuracy, consensus synthesis, unavailable-model regression |
| `tests/test_input_methods_audit.py` | Cross-input parity across all 5 intake methods (Raw Text, URL, Image OCR, PDF, DOCX, CSV) |
| `tests/test_ui_sync.py` | Streamlit session-state widget lifecycle synchronization, edit persistence, clear-all reliability |
| `tests/test_database.py` | SQLAlchemy engine behavior, password masking, SQL injection resistance, persistence and migration utility |

---

## Testing Verification & Limitations

### Browser Automation Status
- **Environment Reality:** The application is developed and hosted in a minimal Linux/WSL environment lacking native X11/Wayland GUI windowing libraries (`libatk-1.0.so.0`, `libgtk-3.so.0`), which blocks headless Chromium/WebKit binary execution.
- **Documented Testing Alternative:** Full automated HTTP smoke testing was implemented to verify Streamlit routes. A local background test instance was spun up on an isolated port, probed via `/_stcore/health` (HTTP 200 `ok`), validated on the root dashboard page (HTTP 200, verifying full page markup), probed on the WebSocket `/stream` route, and cleanly terminated.
- **Direct Local Verification:** For end-to-end interactive UI verification, investigators can run `streamlit run app.py` and access the dashboard directly via any standard desktop browser at `http://localhost:8501`.

---

## Functional Contracts

### 1. Rule-Based Detector (`src/detector.py`)
```python
def analyze_ad(text: str) -> dict[str, Any]: ...
```

### 2. TF-IDF ML Classifier (`src/ml_model.py`)
```python
def predict_ad_ml(text: str) -> dict[str, Any]: ...
```

### 3. DistilBERT Classifier (`src/hf_model.py`)
```python
def predict_ad_hf(text: str) -> dict[str, Any]: ...
```

### 4. OCR Text Extractor (`src/ocr_engine.py`)
```python
def extract_text_ocr(image: PIL.Image.Image) -> dict[str, Any]: ...
```

### 5. CSV Batch Triage (`src/csv_analyzer.py`)
```python
def run_batch_analysis(df: pd.DataFrame, text_column: str, label_column: str | None = None) -> pd.DataFrame: ...
def export_safe_csv(df: pd.DataFrame) -> str: ...
```

### 6. Secure URL Fetcher (`src/url_fetcher.py`)
```python
def validate_url_syntax(url_str: str) -> dict[str, Any]: ...
def is_safe_ip(ip_str: str) -> tuple[bool, str | None]: ...
def resolve_and_verify_hostname(hostname: str, port: int = 443) -> tuple[bool, list[str], str | None]: ...
def safe_fetch_url(url_str: str, max_redirects: int = 3, timeout_seconds: float = 5.0) -> dict[str, Any]: ...
def analyze_url(url_str: str, fetch_content: bool = True) -> dict[str, Any]: ...
```

### 7. Document Extractor (`src/document_extractor.py`)
```python
def extract_pdf_text(uploaded_file, max_size_mb: float = 10.0, max_pages: int = 30) -> dict[str, Any]: ...
def extract_docx_text(uploaded_file, max_size_mb: float = 10.0, max_decompressed_mb: float = 50.0) -> dict[str, Any]: ...
def extract_document_text(uploaded_file) -> dict[str, Any]: ...
```

### 8. Database Persistence Layer (`src/database.py`)
```python
def mask_db_url(url: str | None) -> str: ...
def normalize_db_url(url: str | None) -> str | None: ...
def get_database_url() -> str | None: ...
def get_engine() -> sqlalchemy.Engine: ...
def init_db(engine: sqlalchemy.Engine | None = None) -> None: ...
def save_advertisement(data: dict[str, Any], engine: sqlalchemy.Engine | None = None) -> int | None: ...
def get_all_advertisements(limit: int = 500, engine: sqlalchemy.Engine | None = None) -> list[dict[str, Any]]: ...
def get_advertisement_by_id(ad_id: int, engine: sqlalchemy.Engine | None = None) -> dict[str, Any] | None: ...
def update_investigation_status(ad_id: int, new_status: str, notes: str = "", engine: sqlalchemy.Engine | None = None) -> bool: ...
def get_dashboard_metrics(engine: sqlalchemy.Engine | None = None) -> dict[str, Any]: ...
def check_database_connection(engine: sqlalchemy.Engine | None = None) -> dict[str, Any]: ...
```

---

## Future Roadmap

- **Phase 6:** Graph-based campaign discovery (cross-case clustering of shared Telegram handles, phone numbers, and IFSC prefixes).
- **Phase 6:** Multilingual translation and transliteration for regional vernacular financial scams (Hinglish, Tamil, Telugu).
