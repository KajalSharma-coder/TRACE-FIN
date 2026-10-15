# TRACE//FIN Requirements Checklist

This checklist tracks requirements stated in the repository's README problem statement and Phase 2–5 specifications. Statuses reflect repository inspection and the test/verification evidence listed below. “Complete and verified” means the available automated checks pass; it does not imply validation on representative production data.

## Original documented requirements

| Requirement | Status | Evidence / remaining work |
|---|---|---|
| Detect financial account/card sale, KYC bypass, account rental/mule recruitment, and suspicious financial solicitation | Complete and verified | `src/detector.py`; detector and risk synthesis regression tests |
| Extract URLs, email addresses, phone numbers, and payment identifiers | Complete and verified | `src/detector.py`; detector and multi-format input tests |
| Mitigate educational, regulatory, and benign-awareness false positives | Implemented but needs verification | Mitigation rules and benign regression examples exist; broader labeled, representative data is not present |
| TF-IDF + Logistic Regression training, PII exclusion, and inference | Partially implemented | Training now uses grouped train/validation/test splits, but grouped held-out comparison on the available synthetic data failed completely (0/132 correct); a representative labeled corpus is needed before this is a reliable baseline |
| Dual-engine rule/ML triage with explainable divergence handling | Complete and verified | `src/detector.py`, `src/analysis_service.py`; synthesis tests |
| Screenshot OCR with editable transcription | Complete and verified | `src/ocr_engine.py`, image page, OCR and input-method tests; OCR CLI availability can vary by host |
| Batch CSV triage and formula-injection-safe export | Complete and verified | `src/csv_analyzer.py`; CSV and security tests |
| Fine-tuned Hugging Face DistilBERT training and inference | Partially implemented | Current checkpoint runs, but its metadata does not establish the exact training task/split. A fresh controlled fine-tune scored perfectly on the synthetic grouped split, which has only eight templates and is insufficient evidence for deployment accuracy |
| Secure URL analysis, redirect validation, SSRF protections, and domain indicators | Implemented but needs verification | `src/url_fetcher.py`; URL/security tests use mocked network paths; DNS rebinding resistance of the actual HTTP connection is not proven by those tests |
| In-memory PDF and DOCX extraction with size/format protections | Complete and verified | `src/document_extractor.py`; document and input-method tests |
| Unified five-mode intake, editable human review, and shared triage pipeline | Complete and verified | `pages/1_Analyze_Advertisement.py`, `src/analysis_service.py`; input-method and session-state tests |
| Case management, Data Explorer, and persistent retrieval | Complete and verified | Streamlit pages and database tests; local SQLite path is covered. Live PostgreSQL credentials were not exercised |
| Neon/PostgreSQL support with SQLite fallback and migration utility | Blocked by external dependencies or credentials | PostgreSQL code and migration utility exist, but there is no configured PostgreSQL credential/service available for an end-to-end live check |
| Security regression coverage (SSRF, formula injection, PII exclusion, SQL handling) | Complete and verified | `tests/test_security.py`, `tests/test_url.py`, `tests/test_csv.py`, `tests/test_ml.py`, `tests/test_database.py` |
| Startup and complete application verification | Complete and verified | Streamlit started successfully with an isolated `/tmp` SQLite database; actual sample inference also completed for both local models |
| Statistical precision/recall/false-positive/false-negative evaluation on suitable labeled data | Partially implemented | Synthetic held-out metrics are documented, alongside template-overfitting limitations. No independent representative labeled dataset is available; no real-world performance claim is made |

## Audit findings and repair log

- **Baseline:** 151 passed, 1 skipped (152 total), before changes in this audit.
- **Risk synthesis defect:** If no heuristic rule matched and all statistical models were unavailable, the synthesis branch reported `LOW RISK`. The missing models were therefore indistinguishable from models agreeing that the content was benign.
- **Repair:** This condition now returns `INSUFFICIENT EVIDENCE`, no numeric score, and a human-review action. The analysis service exposes engine availability/errors, includes those details in evidence, and persistence keeps the risk score null. CSV output also preserves an unavailable score rather than coercing it to zero.
- **Regression coverage:** Added tests for unavailable-model synthesis and service/database persistence.
- **Focused verification after the synthesis/persistence repair:** 51 passed, 1 skipped.
- **Final suite:** 153 passed, 1 skipped (154 collected). The skipped case is the live PostgreSQL integration check because `TEST_DATABASE_URL` is not configured.
- **Application startup:** Streamlit started on the isolated `/tmp` database and was stopped after the startup smoke window. It printed its startup URLs without an application exception.
- **Model inference probe:** TF-IDF (`tfidf-logreg-v1.0`) and local DistilBERT (`distilbert-v1.0`) both loaded and classified a suspicious sample as `High Risk`.

## AI integration audit

- The primary page, image page, and CSV batch flow call the shared analysis service; its canonical path is rule detection → local TF-IDF inference → optional local DistilBERT inference → `compute_unified_verdict`.
- `src/ml_model.py` loads a local scikit-learn/joblib pipeline and runs `predict`/`predict_proba`; no external inference API is called.
- `src/hf_model.py` loads tokenizer and weights from `models/hf_financial_ad_classifier/`, then runs PyTorch inference under `torch.no_grad()`. Training obtains the public base model from Hugging Face Hub; runtime inference uses the local artifact.
- The README's original scope requires TF-IDF and DistilBERT, but does not specify OpenAI or another hosted inference provider. No API client or provider credential is required. `DATABASE_URL` is unrelated to AI; `HF_TOKEN` is currently unused.
- `.env` and `.streamlit/secrets.toml` are Git-ignored; `.env` is not tracked. No obvious hardcoded provider API key was found in source files.
- Real local inference: suspicious sample → both models `High Risk`; documented benign vendor-payment sample → both models `Safe`; canonical verdicts were HIGH RISK and LOW RISK respectively. Simulated missing local DistilBERT weights continue through rule + TF-IDF triage, with an unavailable status and error in evidence.
- A separate free-form sample produced a DistilBERT false positive while TF-IDF said Safe. This is consistent with the README's synthetic-data/generalization warning. It was not masked or used to tune thresholds; broader external validation remains needed.

## Additional recommendations (not original requirements)

- Evaluate rule and model precision/recall on a separately collected, legally usable, representative dataset before using scores for operational prioritization.
- Consider pinning outbound connections to the IP addresses validated during DNS checks to close the DNS time-of-check/time-of-use gap; current tests verify validation logic, not transport-level pinning.
- Add continuous integration that runs the test suite and a temporary-database Streamlit startup smoke check.

## Follow-up audit: model provenance and risk regression

- **Baseline for this follow-up:** 154 passed, 1 skipped before its new tests. The live PostgreSQL integration remains skipped because `TEST_DATABASE_URL` is not configured.
- **DistilBERT provenance:** The local folder contains a complete checkpoint (`config.json`, `model.safetensors`, tokenizer) and metadata with `trained_at`, training configuration, and training results. Its label mapping is `Safe=0`, `High Risk=1`; local inference loads the checkpoint and executes PyTorch softmax. It is a fine-tuned project checkpoint based on `distilbert/distilbert-base-uncased`, not an API model. The model filename alone was not treated as proof.
- **Training data/evaluation caveat:** The 500-row dataset has 247 Safe / 253 High Risk rows and only 8 normalized templates after holder-name normalization. The old checkpoint's training split was 295 examples, but its 25-row validation split had only Safe labels; its validation accuracy of 1.0 is therefore not a valid two-class validation result. Its metadata's existing 180-row test metrics are accuracy 0.7222, high-risk precision 1.0000, recall 0.5968, macro F1 0.7194, weighted F1 0.7300, confusion matrix `[[56, 0], [50, 74]]`. These are historical metrics and were not recomputed after code changes.
- **Split repair:** Future HF training now groups variants with embedded account-holder names together and stratifies distinct groups by class where possible. A current split probe produced train 254 (130 Safe/124 High Risk), validation 114 (51/63), test 132 (66/66). Only eight groups means held-out groups are extremely small; this does not justify retraining.
- **Inference observability/UI:** DistilBERT now returns both class probabilities and its High Risk score through the unified service. The analysis UI displays actual active model status, matched rule evidence/weights, class probabilities, and synthesis branch. No external AI API is required by the documented requirements.
- **Regression coverage:** Added legitimate loan, borderline loan, and severe loan scam checks, including one-safe-model/unavailable-model disagreement. Added normalized fingerprint, both-class split support, and artifact-status checks.
- **Mitigation downgrade repair:** Awareness context could reduce a rule score to zero and then let the one-high/one-safe model mitigation shortcut return LOW RISK despite explicit matched scam rules. The shortcut now requires that no suspicious rule matched; a regression case confirms MEDIUM / 40 and human review when model predictions disagree while matched rule evidence remains.
- **Live model probe:** Severe loan scam sample yielded rules=50, TF-IDF High Risk (confidence/high-risk score 0.6731), DistilBERT High Risk (Safe 0.0387 / High Risk 0.9613), final HIGH RISK / 75. Borderline “Quick loan available...” yielded no rule matches but both synthetic models flagged High Risk, resulting MEDIUM / 50. A legitimate disclosed-term ABC Finance loan ad had no rule matches, TF-IDF Safe, and a DistilBERT false positive (High Risk 0.869); existing verified-financial-context mitigation yielded LOW / 0. This illustrates remaining synthetic-data false-positive risk.
- **Exact screenshot case:** Screenshot/ad text was not attached in the current request context. The above reproducible samples are regression probes, not a claim to have reproduced the screenshot's exact 40/100 output. In the current synthesis, MEDIUM / 40 can result when exactly one statistical model flags High Risk and no rule threat qualifies for a higher branch; with rule score 25–49 plus one model alert, the same floor is applied.
- **Final verification:** Focused suite 51 passed; complete suite 160 passed, 1 skipped. No model was retrained and no existing artifact or user data was replaced.

## Candidate model comparison and training pipeline hardening

- **Dataset audit:** 500 labeled rows (253 High Risk / 247 Safe), 500 unique ad strings, zero exact-text duplicates, zero exact-text label conflicts, 497 unique ID values (6 rows have repeated ID values), 8 normalized text templates (4 per class), and zero templates with conflicting labels. Identifiers in `Advertisement_Text` were previously left in transformer training text; the grouped preparation path now redacts known holder names, long account/card number strings, and IFSC codes. The current legacy checkpoint keeps its old input preprocessing because its metadata does not declare the new preprocessing version.
- **Split:** Shared grouped, stratified split: train 254 (130 Safe/124 High Risk), validation 114 (51/63), held-out test 132 (66/66). Template-group IDs are exposed for disjointness tests. Only two independent template groups/class are available for training and one group/class each for validation and test.
- **Comparison protocol:** `scripts/benchmark_ad_models.py` trains a fresh DistilBERT classifier and a ProsusAI/FinBERT financial-language encoder with a new two-class scam-ad head; original FinBERT sentiment classes are discarded. TF-IDF is fit on training data only. Validation macro-F1 (High Risk recall tie-break) selected fresh DistilBERT; test predictions were computed only after selection. All temporary candidate weights remained under `/tmp`.
- **Measured validation/test metrics at max length 128, one epoch:** TF-IDF validation accuracy 0.4474, high-risk P/R/F1 0/0/0, macro-F1 0.3091; test accuracy 0.0000, high-risk P/R/F1 0/0/0, FNR 1.0, confusion `[[0,66],[66,0]]`. Fresh DistilBERT validation and test accuracy, high-risk precision/recall/F1, and macro-F1 were all 1.0; test FNR 0 and confusion `[[66,0],[0,66]]`. FinBERT-head tuning produced the same reported metrics. These rows are variants of only eight templates; they do not represent independent real advertisements.
- **Candidate disposition:** The existing DistilBERT checkpoint was excluded from selection because it has no row/template training manifest and its old training split was not the shared grouped split. Despite the new candidates’ perfect synthetic holdout, no checkpoint was promoted or installed as default: the dataset has no representative legitimate loan or real-world scam-ad coverage, so claiming improvement or replacing the runtime model would be unsupported.
- **Implementation changes:** The TF-IDF trainer now consumes the same grouped split, records validation and test metrics plus false-negative rate, and does not fit vocabulary on validation/test. HF training metadata now records task/preprocessing provenance; inference validates the class map and output width, keeps confidence as model confidence, and reports its 128-token truncation. Legacy checkpoint UI status now says task provenance is unverified instead of claiming a specific dataset.
- **External model source:** Public ProsusAI/FinBERT weights were downloaded to `/tmp` for this controlled experiment only. Its published labels are positive/negative/neutral financial sentiment, not scam labels.
- **Regression tests:** Added end-to-end legitimate and suspicious loan examples, PII normalization/split-disjointness checks, bad label-map rejection, and long-input truncation checks.
- **Final verification for this follow-up:** Focused model/HF tests passed (25), focused loan/model/intake checks passed (26), and the complete suite passed (163 passed, 1 skipped).
