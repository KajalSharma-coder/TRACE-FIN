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

## Phase 4: Multi-Modal, Batch Processing & DistilBERT Fine-Tuning

### Feature A: Image & Screenshot OCR Analysis (`pages/4_Image_Analysis.py`)
- Upload JPG, JPEG, PNG, or WEBP screenshots with size (max 10MB) and dimension (50-8000px) validation.
- Extracts advertisement text locally using Tesseract OCR with character confidence scoring.
- Displays extracted text in an editable text area before analysis, allowing human investigators to correct OCR transcription errors.
- Runs text through Rule Heuristics, TF-IDF Classifier, and DistilBERT with separate indicators.
- **Privacy Assurance:** Images are processed in-memory and are **never** persisted to disk or sent to external cloud APIs.

### Feature B: Batch CSV Advertisement Analysis (`pages/5_Batch_CSV_Analysis.py`)
- Upload CSV datasets up to 5,000 rows and 50MB. Auto-detects UTF-8, Latin-1, and CP1252 encodings.
- Column mapping configuration: select advertisement text column and optional ground-truth label column.
- Live progress indicator during batch execution across all triage engines.
- **Spreadsheet Formula Injection Defense:** Neutralizes dangerous prefixes (`=`, `+`, `-`, `@`, `\t`, `\r`) with tab-character prepending on exported CSV files.

### Feature C & D: Hugging Face DistilBERT Fine-Tuning (`src/hf_model.py`, `scripts/train_hf_model.py`)
- Base model: `distilbert/distilbert-base-uncased` with AutoTokenizer and AutoModelForSequenceClassification.
- **Strict PII Exclusion:** Never uses `ID_No`, `Account_Holder_Name`, `Bank_Account_No`, or `IFSC_Code`.
- **Grouped Template Splitting:** Groups syntactic template fingerprints (first 35 characters) into isolated train/val/test partitions to prevent near-identical phrasing from leaking across evaluation splits.
- **CLI Training Script:** Configurable epochs, batch size, learning rate, random seed, device selection (auto-detects CUDA/CPU), and held-out test evaluation.
- Backs up previous model directories before saving weights, tokenizer files, and metadata to `models/hf_financial_ad_classifier/`.

---

## Phase 5: Multi-Format Intake, Secure URL Analysis & Hardened Verification

### Feature A: Secure URL Analysis & SSRF Mitigation (`src/url_fetcher.py`)
- **Strict Syntax & Scheme Control:** Restricts schemes strictly to `http://` and `https://`. Blocks embedded credentials (`user:pass@host`), malformed hostnames, and arbitrary URI protocols (`file://`, `ftp://`, `javascript:`, `data:`).
- **SSRF Network Protection:**
  - Blocks loopback (`127.0.0.0/8`, `::1`), private RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), link-local (`169.254.0.0/16`, `fe80::/10`), multicast (`224.0.0.0/4`), unspecified (`0.0.0.0`), and cloud metadata endpoints (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`).
  - Pre-flight DNS resolution verification via `socket.getaddrinfo()`. If any resolved IP points to a private/internal range, the request is immediately aborted before socket connection.
- **Manual Redirect Chain Validation:** Disables automatic HTTP client redirect following. Inspects and re-validates the hostname and IP destination of every redirect hop (up to 3 hops max), preventing open-redirect SSRF bypasses.
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
  3. `🖼️ Screenshot / Image` (Tesseract OCR preview & transcription)
  4. `📄 PDF Document` (Page count, metadata & extraction)
  5. `📑 Word Document (DOCX)` (Paragraph & table extraction)
- **Mandatory Human Review Step:** Extracted content is presented in an editable text area alongside source metadata, character/word counters, and extraction warnings. The investigator retains full authority to review, sanitize, or edit the content before initiating detection.
- **Triple-Engine Triage:** Running analysis triggers Heuristic Rules + TF-IDF Classifier + Hugging Face DistilBERT simultaneously, generating consensus scoring and explainable indicator breakdowns.

### Feature D: Hardened Security & Regression Suite (`tests/test_security.py`, `tests/test_url.py`, `tests/test_docs.py`)
- Full 86-test automated regression suite with 100% pass rate.
- Security test matrix explicitly validating SSRF defense boundaries, CSV formula injection vectors, PII exclusion from model pipelines, and SQLite database record persistence.

---

## Project Structure

```
trace-fin/
├── app.py                         # Threat Intelligence Dashboard (Overview, KPIs, Charts)
├── config.py                      # Design tokens, paths, standardized risk tiers (v0.5.0-phase5)
├── requirements.txt               # Dependencies (Streamlit, Torch, Transformers, Pytesseract, etc.)
├── README.md                      # Comprehensive documentation
├── data/
│   ├── back.dataset.csv           # Primary financial advertisement dataset (500 records)
│   ├── cleaned_spam_dataset.csv   # General SMS spam dataset (isolated)
│   └── tracefin.db                # SQLite persistent storage (WAL mode, automated schema migration)
├── models/
│   ├── financial_ad_classifier.joblib      # Trained scikit-learn TF-IDF + LogReg pipeline
│   ├── model_metrics.json                 # Persisted TF-IDF evaluation metrics and feature weights
│   └── hf_financial_ad_classifier/        # Fine-tuned DistilBERT weights, tokenizer & metadata
├── pages/
│   ├── 1_Analyze_Advertisement.py # Unified Multi-Format Console (Text, URL, Image, PDF, DOCX)
│   ├── 2_Investigation_Cases.py   # Case Management, Filter, Status Workflow & Details
│   ├── 3_Data_Explorer.py         # Tabular Browser, Multi-indicator Filter, Forensic CSV Export
│   ├── 4_Image_Analysis.py        # Screenshot & Image OCR Intake, Text Correction & Triage
│   └── 5_Batch_CSV_Analysis.py    # Bulk CSV Intake, Column Mapping & Formula-Safe Export
├── scripts/
│   ├── train_model.py             # Reproducible TF-IDF + LogReg training CLI
│   └── train_hf_model.py          # Hugging Face DistilBERT fine-tuning & evaluation CLI
├── src/
│   ├── database.py                # SQLite persistence layer (idempotent schema migrations)
│   ├── detector.py                # Explainable rule-based heuristic detection engine (Phase 2)
│   ├── ml_model.py                # TF-IDF + LogReg ML pipeline, training & consensus (Phase 3)
│   ├── hf_model.py                # DistilBERT dataset grouping, training & inference (Phase 4)
│   ├── ocr_engine.py              # Tesseract OCR extraction and image validation (Phase 4)
│   ├── csv_analyzer.py            # Batch CSV validation, triage engine & formula sanitizer (Phase 4)
│   ├── url_fetcher.py             # Secure URL validator, SSRF mitigation & HTML parser (Phase 5)
│   ├── document_extractor.py      # PDF & DOCX in-memory text extraction & safety caps (Phase 5)
│   ├── sample_data.py             # Synthetic demonstration records
│   └── ui_components.py           # Reusable dark cybersecurity console UI components
└── tests/
    ├── test_detector.py           # Phase 2 test suite (20 heuristic tests)
    ├── test_ml.py                 # Phase 3 test suite (15 dataset, ML & consensus tests)
    ├── test_ocr.py                # Phase 4 test suite (9 image validation & OCR tests)
    ├── test_csv.py                # Phase 4 test suite (7 CSV validation & sanitization tests)
    ├── test_hf.py                 # Phase 4 test suite (6 DistilBERT dependency & dataset tests)
    ├── test_url.py                # Phase 5 test suite (17 URL syntax, SSRF & redirect tests)
    ├── test_docs.py               # Phase 5 test suite (7 PDF & DOCX safety extraction tests)
    └── test_security.py           # Phase 5 security matrix (5 SSRF, CSV injection, PII tests)
```

---

## Installation & Setup

### Environment Requirements
- Python 3.12+ (tested on Python 3.14 under Linux/WSL).
- System Tesseract OCR:
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

### Running the Application

```bash
streamlit run app.py
```

Open your browser at **`http://localhost:8501`**.

The SQLite database initializes automatically at `data/tracefin.db`. Existing records are safely migrated without data loss.

### Running the Full Test Suite

```bash
# Run all 86 tests across all 8 test modules
pytest -v
```

Coverage (86 passed tests, 100% pass rate):
- **Heuristics (20 tests):** Empty inputs, benign banking, educational notices, account sales, KYC bypass, mule recruitment, urgency/secrecy, indicator extraction, score bounds.
- **TF-IDF ML (15 tests):** Token preprocessing, dataset integrity, spam dataset isolation, PII exclusion, reproducible pipeline training, positive/negative class inference, fallback handling, consensus/divergence logic, and database persistence.
- **OCR Engine (9 tests):** Valid JPEG/PNG/WEBP, empty/corrupt files, undersized/oversized dimensions, None handling, and Tesseract availability.
- **CSV Batch Processor (7 tests):** Formula injection neutralization (`=`, `+`, `-`, `@`, `\t`), valid/empty/header-only CSV validation, batch triage execution, and safe export.
- **Hugging Face DistilBERT (6 tests):** Dependency checks, template fingerprinting, grouped partition preparation, class balance verification, empty text inference handling, and missing model fallback.
- **Secure URL Analysis (17 tests):** Scheme/credential validation, IPv4/IPv6 loopback & private range blocking, cloud metadata host filtering, DNS pre-resolution checks, DNS rebinding mitigation, redirect hop validation, HTML text extraction, and syntax-only mode.
- **Document Extractor (7 tests):** PDF header validation, scanned PDF blank warnings, DOCX paragraphs and tables, corrupted ZIP archives, decompression ratio limits (ZIP bomb defense), and format router.
- **Security Matrix (5 tests):** Multi-hop SSRF boundary matrix, CSV formula injection evasion characters, strict PII exclusion from model inference, and database preservation guarantees.

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

---

## Future Roadmap

- **Phase 6:** Graph-based campaign discovery (cross-case clustering of shared Telegram handles, phone numbers, and IFSC prefixes).
- **Phase 6:** Multilingual translation and transliteration for regional vernacular financial scams (Hinglish, Tamil, Telugu).
