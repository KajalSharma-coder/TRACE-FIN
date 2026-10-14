"""
TRACE//FIN — Machine Learning Detection Module (Phase 3)
Reproducible TF-IDF + Logistic Regression baseline trained on suspicious financial advertisement text.
Provides ML inference, evaluation metrics, feature extraction, and dual-engine consensus analysis.
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from config import DATASET_PATH, METRICS_PATH, MODEL_PATH, MODELS_DIR

logger = logging.getLogger("tracefin.ml")

MODEL_VERSION = "tfidf-logreg-v1.0"
RANDOM_STATE = 42
TEST_SIZE = 0.20

# Strictly prohibited identifier columns that must NEVER be used as features
EXCLUDED_COLUMNS = ["ID_No", "Account_Holder_Name", "Bank_Account_No", "IFSC_Code"]

# ── Text Preprocessing & Token Normalization ───────────────────────────

def preprocess_text(text: str) -> str:
    """
    Normalize text before TF-IDF vectorization to avoid memorizing synthetic
    identifiers (specific bank account digits, Indian names, or IFSC strings).
    Preserves operational semantic keywords (e.g. 'selling kyc account', 'hawala', 'rent').
    """
    if not isinstance(text, str):
        return ""

    # Normalize IFSC codes (e.g., HDFC0437589, ICIC0755396)
    cleaned = re.sub(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", " <IFSC_CODE> ", text, flags=re.IGNORECASE)

    # Normalize UPI handles (e.g., pay@okaxis)
    cleaned = re.sub(r"[a-zA-Z0-9.\-_]{2,49}@[a-zA-Z]{2,}", " <UPI_HANDLE> ", cleaned)

    # Normalize long digit sequences representing bank accounts or card numbers
    cleaned = re.sub(r"\b\d{4,}\b", " <ACCOUNT_NUM> ", cleaned)

    # Normalize amounts with shorthand (e.g., 10k/month, 50k)
    cleaned = re.sub(r"\b\d+k(?:\s*/\s*(?:month|day|hr|week))?\b", " <RENTAL_AMOUNT> ", cleaned, flags=re.IGNORECASE)

    # Normalize URLs
    cleaned = re.sub(r"https?://\S+|www\.\S+", " <URL> ", cleaned, flags=re.IGNORECASE)

    # Normalize extra whitespaces and lowercase
    cleaned = " ".join(cleaned.lower().split())
    return cleaned


# ── Model Training & Artifact Generation ───────────────────────────────

def train_model(
    dataset_path: Path = DATASET_PATH,
    model_path: Path = MODEL_PATH,
    metrics_path: Path = METRICS_PATH,
    random_state: int = RANDOM_STATE,
    test_size: float = TEST_SIZE,
) -> Dict[str, Any]:
    """
    Train a reproducible TF-IDF + Logistic Regression text classification baseline.
    
    1. Loads back.dataset.csv.
    2. Validates schema and strictly excludes PII/identifier columns.
    3. Normalizes tokens to prevent synthetic template memorization of account numbers.
    4. Performs stratified train/test split.
    5. Fits vectorizer strictly on training split only (zero data leakage).
    6. Evaluates test set and saves artifacts to models/.
    """
    if not dataset_path.exists():
        raise FileNotFoundError(f"Training dataset not found at: {dataset_path}")

    # Load dataset
    df = pd.read_csv(dataset_path)

    # Validate required columns
    required_cols = ["Advertisement_Text", "Risk_Label"]
    for col in required_cols:
        if col not in df.columns:
            raise ValueError(f"Required column '{col}' missing from dataset {dataset_path}")

    # Enforce strict exclusion of PII and identifier columns
    available_cols = set(df.columns)
    for forbidden in EXCLUDED_COLUMNS:
        if forbidden in available_cols:
            logger.info("Enforcing exclusion of identifier column: %s", forbidden)

    # Map target: High Risk -> 1 (Positive), Safe -> 0 (Negative)
    label_map = {"Safe": 0, "High Risk": 1}
    unrecognized = set(df["Risk_Label"].unique()) - set(label_map.keys())
    if unrecognized:
        raise ValueError(f"Unrecognized labels in Risk_Label column: {unrecognized}")

    # Feature extraction and preprocessing
    X_raw = df["Advertisement_Text"].astype(str)
    X_clean = X_raw.apply(preprocess_text)
    y = df["Risk_Label"].map(label_map).values

    # Stratified train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X_clean,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )

    # Pipeline definition: sublinear_tf scales down repeated tokens, min_df eliminates singletons
    pipeline = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                ngram_range=(1, 2),
                min_df=2,
                max_df=0.98,
                sublinear_tf=True,
                stop_words="english",
            ),
        ),
        (
            "clf",
            LogisticRegression(
                C=1.0,
                random_state=random_state,
                class_weight="balanced",
                max_iter=1000,
                solver="lbfgs",
            ),
        ),
    ])

    # Fit pipeline on training data only
    pipeline.fit(X_train, y_train)

    # Evaluate on held-out test split
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    report = classification_report(
        y_test,
        y_pred,
        target_names=["Safe", "High Risk"],
        output_dict=True,
    )
    cm = confusion_matrix(y_test, y_pred).tolist()

    # Extract top influential vocabulary features
    vec: TfidfVectorizer = pipeline.named_steps["tfidf"]
    clf: LogisticRegression = pipeline.named_steps["clf"]
    feature_names = np.array(vec.get_feature_names_out())
    coefs = clf.coef_[0]

    top_high_risk_idx = np.argsort(coefs)[-12:][::-1]
    top_safe_idx = np.argsort(coefs)[:12]

    top_high_risk_features = [
        {"feature": str(feature_names[i]), "weight": round(float(coefs[i]), 4)}
        for i in top_high_risk_idx
    ]
    top_safe_features = [
        {"feature": str(feature_names[i]), "weight": round(float(coefs[i]), 4)}
        for i in top_safe_idx
    ]

    # Metrics and metadata dictionary
    metrics = {
        "model_version": MODEL_VERSION,
        "algorithm": "TF-IDF (1,2-grams) + LogisticRegression",
        "random_state": random_state,
        "dataset_path": str(dataset_path),
        "total_samples": int(len(df)),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "class_distribution": {
            "total": {
                "High Risk": int((y == 1).sum()),
                "Safe": int((y == 0).sum()),
            },
            "train": {
                "High Risk": int((y_train == 1).sum()),
                "Safe": int((y_train == 0).sum()),
            },
            "test": {
                "High Risk": int((y_test == 1).sum()),
                "Safe": int((y_test == 0).sum()),
            },
        },
        "accuracy": round(acc, 4),
        "confusion_matrix": {
            "true_negatives_safe": cm[0][0],
            "false_positives": cm[0][1],
            "false_negatives": cm[1][0],
            "true_positives_high_risk": cm[1][1],
        },
        "classification_report": {
            "Safe": {
                "precision": round(report["Safe"]["precision"], 4),
                "recall": round(report["Safe"]["recall"], 4),
                "f1_score": round(report["Safe"]["f1-score"], 4),
                "support": report["Safe"]["support"],
            },
            "High Risk": {
                "precision": round(report["High Risk"]["precision"], 4),
                "recall": round(report["High Risk"]["recall"], 4),
                "f1_score": round(report["High Risk"]["f1-score"], 4),
                "support": report["High Risk"]["support"],
            },
            "macro_avg_f1": round(report["macro avg"]["f1-score"], 4),
        },
        "top_features": {
            "high_risk_signals": top_high_risk_features,
            "safe_signals": top_safe_features,
        },
        "limitations": [
            "Trained on back.dataset.csv (500 synthetic records with 4 distinct syntactic templates per class).",
            "High test metrics (100% on synthetic split) reflect template memorization within this narrow distribution.",
            "May exhibit false negatives on real-world phrasing with unseen criminal vernacular.",
            "Must be utilized in conjunction with the explainable rule-based detector.",
        ],
    }

    # Ensure models directory exists and save artifacts
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, model_path)

    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    logger.info("Saved trained ML model to: %s", model_path)
    logger.info("Saved ML metrics to: %s", metrics_path)
    return metrics


# ── Model Loading & Inference API ──────────────────────────────────────

_CACHED_MODEL: Optional[Pipeline] = None
_CACHED_MODEL_PATH: Optional[Path] = None
_CACHED_METRICS: Optional[Dict[str, Any]] = None
_CACHED_METRICS_PATH: Optional[Path] = None


def load_model(
    model_path: Path = MODEL_PATH,
    force_reload: bool = False,
) -> Optional[Pipeline]:
    """Load model pipeline from disk with in-memory caching."""
    global _CACHED_MODEL, _CACHED_MODEL_PATH
    if _CACHED_MODEL is not None and _CACHED_MODEL_PATH == model_path and not force_reload:
        return _CACHED_MODEL

    if not model_path.exists():
        return None

    try:
        _CACHED_MODEL = joblib.load(model_path)
        _CACHED_MODEL_PATH = model_path
        return _CACHED_MODEL
    except Exception as exc:
        logger.error("Failed to load model from %s: %s", model_path, exc)
        return None


def get_model_metrics(
    metrics_path: Path = METRICS_PATH,
    force_reload: bool = False,
) -> Optional[Dict[str, Any]]:
    """Load stored evaluation metrics from disk."""
    global _CACHED_METRICS, _CACHED_METRICS_PATH
    if _CACHED_METRICS is not None and _CACHED_METRICS_PATH == metrics_path and not force_reload:
        return _CACHED_METRICS

    if not metrics_path.exists():
        return None

    try:
        with open(metrics_path, "r", encoding="utf-8") as f:
            _CACHED_METRICS = json.load(f)
        _CACHED_METRICS_PATH = metrics_path
        return _CACHED_METRICS
    except Exception as exc:
        logger.error("Failed to read metrics from %s: %s", metrics_path, exc)
        return None


def predict_ad_ml(
    text: str,
    model_path: Path = MODEL_PATH,
) -> Dict[str, Any]:
    """
    Run ML inference on advertisement text.
    
    Returns a structured dictionary with:
    - available: bool (False if model file is missing or text invalid)
    - risk_label: 'High Risk' | 'Safe' | None
    - high_risk_score: float (0.0 to 1.0) — raw model score for the positive class
    - confidence: float (0.0 to 1.0)
    - model_version: str
    - top_signals: list of active vocabulary features contributing to the prediction
    - disclaimer: honest documentation that scores are synthetic logistic decisions, not calibrated probabilities
    """
    model = load_model(model_path=model_path)

    if model is None:
        return {
            "available": False,
            "prediction": None,
            "risk_label": None,
            "high_risk_score": None,
            "confidence": None,
            "confidence_pct": None,
            "model_version": None,
            "top_signals": [],
            "error": "ML model artifact not found. Run training script to generate models/financial_ad_classifier.joblib.",
            "disclaimer": "ML assessment unavailable. Rely on Phase 2 explainable rule-based engine.",
        }

    if not text or not text.strip():
        return {
            "available": False,
            "prediction": None,
            "risk_label": None,
            "high_risk_score": None,
            "confidence": None,
            "confidence_pct": None,
            "model_version": MODEL_VERSION,
            "top_signals": [],
            "error": "Input text is empty.",
            "disclaimer": "Cannot analyze empty text.",
        }

    clean_text = preprocess_text(text)
    if not clean_text:
        clean_text = text.lower()

    try:
        # Predict class & probability
        pred_class = int(model.predict([clean_text])[0])
        probs = model.predict_proba([clean_text])[0]
        p_safe = float(probs[0])
        p_high_risk = float(probs[1])

        risk_label = "High Risk" if pred_class == 1 else "Safe"
        confidence = float(max(p_safe, p_high_risk))
        high_risk_score = p_high_risk

        # Extract active vocabulary features in input
        top_signals: List[Dict[str, Any]] = []
        try:
            vec: TfidfVectorizer = model.named_steps["tfidf"]
            clf: LogisticRegression = model.named_steps["clf"]
            feature_names = vec.get_feature_names_out()
            coefs = clf.coef_[0]

            tfidf_vec = vec.transform([clean_text])
            non_zeros = tfidf_vec.nonzero()[1]

            signals = []
            for col_idx in non_zeros:
                tok = feature_names[col_idx]
                tfidf_val = tfidf_vec[0, col_idx]
                w = coefs[col_idx]
                contribution = tfidf_val * w
                signals.append((contribution, tok, w))

            # Sort by absolute contribution
            signals.sort(key=lambda s: abs(s[0]), reverse=True)
            for contrib, tok, w in signals[:6]:
                top_signals.append({
                    "token": tok,
                    "direction": "High Risk" if w > 0 else "Safe",
                    "weight": round(float(w), 3),
                    "impact": round(float(contrib), 3),
                })
        except Exception as sig_err:
            logger.debug("Could not extract local ML signals: %s", sig_err)

        return {
            "available": True,
            "prediction": pred_class,
            "risk_label": risk_label,
            "high_risk_score": round(high_risk_score, 4),
            "confidence": round(confidence, 4),
            "confidence_pct": round(confidence * 100, 1),
            "model_version": MODEL_VERSION,
            "top_signals": top_signals,
            "error": None,
            "disclaimer": (
                "ML decision scores reflect distance to hyper-plane on the synthetic training distribution, "
                "not calibrated real-world crime probabilities. Human review is required."
            ),
        }
    except Exception as exc:
        logger.error("Inference failed: %s", exc)
        return {
            "available": False,
            "prediction": None,
            "risk_label": None,
            "high_risk_score": None,
            "confidence": None,
            "confidence_pct": None,
            "model_version": MODEL_VERSION,
            "top_signals": [],
            "error": f"Inference exception: {exc}",
            "disclaimer": "Error occurred during ML scoring.",
        }


# ── Dual-Engine Consensus & Comparison ─────────────────────────────────

def compare_rule_and_ml(
    rule_result: Dict[str, Any],
    ml_result: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Compare outputs from the rule-based heuristic detector (Phase 2) and the
    ML classification baseline (Phase 3).
    
    Identifies agreement (Consensus) or discrepancy (Divergence) and provides
    guidance to prevent investigators from being misled by model blind spots.
    """
    if not ml_result.get("available"):
        return {
            "status": "Standalone Rule-Based",
            "badge_color": "#3b82f6",
            "is_divergent": False,
            "summary": "Rule-based engine operated without active ML baseline.",
            "recommendation": "Rely on explainable heuristic evidence.",
        }

    rule_level = str(rule_result.get("risk_level", "Low")).capitalize()
    rule_is_threat = rule_level in ("Critical", "High", "Medium")
    ml_label = ml_result.get("risk_label")
    ml_is_threat = (ml_label == "High Risk")

    if rule_is_threat and ml_is_threat:
        return {
            "status": "Consensus: High Risk Threat",
            "badge_color": "#ef4444",
            "is_divergent": False,
            "summary": f"Dual-Engine Agreement: Heuristic rules ({rule_level}, score {rule_result.get('risk_score', 0)}) and ML baseline ({ml_label}, {ml_result.get('confidence_pct', 0)}%) both flagged this advertisement as suspicious.",
            "recommendation": "High priority: Expedite case opening and preserve extracted payment/contact identifiers.",
        }
    elif not rule_is_threat and not ml_is_threat:
        return {
            "status": "Consensus: Benign / Safe",
            "badge_color": "#22c55e",
            "is_divergent": False,
            "summary": "Dual-Engine Agreement: Neither heuristic rules nor ML baseline identified suspicious financial advertisements.",
            "recommendation": "Routine: Low priority for immediate investigative triage.",
        }
    elif rule_is_threat and not ml_is_threat:
        return {
            "status": "Divergence: Rule Engine Alert",
            "badge_color": "#f97316",
            "is_divergent": True,
            "summary": f"Heuristic rules flagged {rule_level} risk, but ML predicted 'Safe'. This typically indicates novel, out-of-distribution criminal phrasing not covered by the synthetic training templates.",
            "recommendation": "Prioritize rule-based evidence: Inspect matched categories and explicit trigger phrases.",
        }
    else:  # not rule_is_threat and ml_is_threat
        return {
            "status": "Divergence: ML Anomaly Alert",
            "badge_color": "#eab308",
            "is_divergent": True,
            "summary": "ML classified ad as 'High Risk' based on vocabulary correlation, but heuristic rules did not fire.",
            "recommendation": "Investigator check: Review top ML signal tokens to verify if benign financial terms caused false correlation.",
        }
