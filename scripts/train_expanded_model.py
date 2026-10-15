"""Train and validation-select an expanded, externally sourced scam-message model.

The original model is never overwritten. The manually labelled Mendeley corpus
provides grouped validation and test partitions; the test partition is only
used after validation-based candidate selection.
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import (  # noqa: E402
    DATASET_PATH,
    EXPANDED_DATASET_PATH,
    EXPANDED_METRICS_PATH,
    EXPANDED_MODEL_PATH,
    MODEL_PATH,
    MODEL_SELECTION_PATH,
)
from src.hf_model import _extract_template_fingerprint, prepare_dataset  # noqa: E402
from src.ml_model import preprocess_text  # noqa: E402

HF_DATA = ROOT / "data/external/anmolshrivastav_scam-ham-india.csv"
MENDELEY_DATA = ROOT / "data/external/mendeley_financial_scams_v2.csv"
RANDOM_STATE = 42


def redact_identifiers(value: Any) -> str:
    """Remove contact identifiers while retaining a generic URL signal."""
    text = str(value or "")
    text = re.sub(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", " <EMAIL> ", text)
    text = re.sub(r"https?://\S+|www\.\S+", " <URL> ", text, flags=re.I)
    text = re.sub(r"(?<!\w)\+?\d[\d ()-]{8,}\d(?!\w)", " <PHONE> ", text)
    return " ".join(text.split())


def _metrics(y_true: list[int], y_pred: np.ndarray) -> dict[str, Any]:
    report = classification_report(
        y_true, y_pred, labels=[0, 1], target_names=["Safe", "High Risk"],
        output_dict=True, zero_division=0,
    )
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision_macro": round(float(report["macro avg"]["precision"]), 4),
        "recall_macro": round(float(report["macro avg"]["recall"]), 4),
        "f1_macro": round(float(report["macro avg"]["f1-score"]), 4),
        "precision_by_class": {
            label: round(float(report[label]["precision"]), 4)
            for label in ("Safe", "High Risk")
        },
        "recall_by_class": {
            label: round(float(report[label]["recall"]), 4)
            for label in ("Safe", "High Risk")
        },
        "f1_by_class": {
            label: round(float(report[label]["f1-score"]), 4)
            for label in ("Safe", "High Risk")
        },
        "confusion_matrix_labels": ["Safe", "High Risk"],
        "confusion_matrix": cm.tolist(),
        "false_negative_rate": round(float(cm[1, 0] / cm[1].sum()), 4)
        if cm[1].sum() else None,
        "samples": len(y_true),
    }


def _new_pipeline() -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2), min_df=2, max_df=0.98, sublinear_tf=True,
            stop_words="english",
        )),
        ("clf", LogisticRegression(
            C=1.0, random_state=RANDOM_STATE, class_weight="balanced",
            max_iter=1000, solver="lbfgs",
        )),
    ])


def _load_mendeley_splits() -> tuple[dict[str, Any], dict[str, int]]:
    if not MENDELEY_DATA.is_file():
        raise FileNotFoundError(f"Required sourced dataset missing: {MENDELEY_DATA}")
    raw = pd.read_csv(MENDELEY_DATA).fillna("")
    source_rows = len(raw)
    required = {"label", "message"}
    if not required.issubset(raw.columns):
        raise ValueError(f"Mendeley dataset needs columns {sorted(required)}")
    label_map = {"ham": "Safe", "scam": "High Risk"}
    raw["Risk_Label"] = raw["label"].astype(str).str.strip().str.lower().map(label_map)
    raw["Advertisement_Text"] = raw["message"].map(redact_identifiers)
    raw = raw[raw["Risk_Label"].notna() & raw["Advertisement_Text"].ne("")].copy()
    before_dedup = len(raw)
    raw = raw.drop_duplicates(subset=["Advertisement_Text", "Risk_Label"])
    duplicate_rows_removed = before_dedup - len(raw)
    raw["_fingerprint"] = raw["Advertisement_Text"].map(_extract_template_fingerprint)

    # Conflicting labels on one normalized template are ambiguous supervision.
    conflicting = set(raw.groupby("_fingerprint")["Risk_Label"].nunique().loc[lambda s: s > 1].index)
    conflicting_rows_removed = int(raw["_fingerprint"].isin(conflicting).sum())
    raw = raw[~raw["_fingerprint"].isin(conflicting)].copy()
    if raw["Risk_Label"].nunique() != 2:
        raise ValueError("Mendeley corpus no longer has both classes after quality filtering")

    with tempfile.TemporaryDirectory(prefix="tracefin-scam-split-") as temp_dir:
        split_path = Path(temp_dir) / "mendeley_clean.csv"
        raw[["Advertisement_Text", "Risk_Label"]].to_csv(split_path, index=False)
        split = prepare_dataset(split_path, random_state=RANDOM_STATE)
    counts = {
        "source_rows": source_rows,
        "usable_rows": int(len(raw)),
        "conflicting_template_groups_excluded": len(conflicting),
        "exact_duplicate_rows_removed": duplicate_rows_removed,
        "conflicting_template_rows_removed": conflicting_rows_removed,
    }
    return split, counts


def _existing_model() -> Pipeline:
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(f"Original model artifact missing: {MODEL_PATH}")
    model = joblib.load(MODEL_PATH)
    if not hasattr(model, "predict"):
        raise TypeError("Original model artifact does not expose predict()")
    return model


def main() -> dict[str, Any]:
    message_split, data_quality = _load_mendeley_splits()
    # Preserve a truly held-out slice of the actual financial-ad corpus too.
    # All source-ad records outside this grouped training partition stay out of
    # candidate fitting, even though the legacy model may have seen them.
    ad_split = prepare_dataset(DATASET_PATH, random_state=RANDOM_STATE)
    ad_heldout_texts = {
        preprocess_text(text)
        for text in ad_split["val_texts"] + ad_split["test_texts"]
    }
    message_heldout_texts = {
        preprocess_text(text)
        for text in message_split["val_texts"] + message_split["test_texts"]
    }

    # Existing financial-ad records are supplemental training rows, not a new
    # evaluation set. They remain stored unchanged in back.dataset.csv.
    ads_rows = pd.DataFrame({
        "text": [redact_identifiers(t) for t in ad_split["train_texts"]],
        "label": ad_split["train_labels"],
        "source": "existing_back_dataset",
    })

    # The Indian public corpus is ham/spam messages rather than ads and its
    # card discloses a real/augmented mixture. It contributes training rows
    # only; we cannot distinguish synthetic rows because it has no row source.
    if not HF_DATA.is_file():
        raise FileNotFoundError(f"Required sourced dataset missing: {HF_DATA}")
    indian = pd.read_csv(HF_DATA).fillna("")
    indian_rows = pd.DataFrame({
        "text": [redact_identifiers(t) for t in indian["text"]],
        "label": indian["label"].astype(str).str.lower().map({"ham": 0, "spam": 1}),
        "source": "indian_scam_ham_mixed_provenance",
    })
    indian_rows = indian_rows.dropna(subset=["label"])
    indian_rows = indian_rows[indian_rows["text"].str.strip().ne("")]

    mendeley_train = pd.DataFrame({
        "text": message_split["train_texts"],
        "label": message_split["train_labels"],
        "source": "mendeley_train",
    })

    training = pd.concat([ads_rows, indian_rows, mendeley_train], ignore_index=True)
    pre_quality_source_counts = dict(Counter(training["source"]))
    training["text"] = training["text"].map(preprocess_text)
    is_ad_train = training["source"].eq("existing_back_dataset")
    ad_train_overlaps_message_holdout = is_ad_train & training["text"].isin(message_heldout_texts)
    external_overlaps_any_holdout = (~is_ad_train) & training["text"].isin(
        ad_heldout_texts | message_heldout_texts
    )
    overlap_rows_removed = int((ad_train_overlaps_message_holdout | external_overlaps_any_holdout).sum())
    training = training[~(ad_train_overlaps_message_holdout | external_overlaps_any_holdout)]
    empty_text_rows_removed = int(training["text"].astype(str).str.strip().eq("").sum())
    training = training[training["text"].str.strip().ne("")].reset_index(drop=True)
    # Exact duplicate text with different labels is unsafe; remove all such
    # rows. Exact duplicates with a consistent label are represented once.
    label_counts = training.groupby("text")["label"].nunique()
    conflicting_texts = set(label_counts[label_counts > 1].index)
    conflicting_rows_removed = int(training["text"].isin(conflicting_texts).sum())
    training = training[~training["text"].isin(conflicting_texts)]
    rows_before_dedup = len(training)
    training = training.drop_duplicates(subset=["text", "label"])
    exact_duplicate_rows_removed = rows_before_dedup - len(training)
    training = training.reset_index(drop=True)
    training["label"] = training["label"].astype(int)
    if set(training["label"]) != {0, 1}:
        raise ValueError("Training sources must provide both Safe and High Risk examples")

    # Save the exact expanded training corpus with source provenance.
    EXPANDED_DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    training[["text", "label", "source"]].to_csv(EXPANDED_DATASET_PATH, index=False)

    candidate = _new_pipeline()
    candidate.fit(training["text"].tolist(), training["label"].to_numpy())
    baseline = _existing_model()
    # This reference is trained solely on the grouped ad training partition.
    # The checked-in legacy model used a 400/100 row split on eight templates,
    # so its original ad test metrics are not leakage-free evidence.
    ad_reference = _new_pipeline()
    ad_reference.fit(
        [preprocess_text(t) for t in ad_split["train_texts"]],
        np.asarray(ad_split["train_labels"], dtype=int),
    )

    def evaluate_validation(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        val_x = [preprocess_text(t) for t in data["val_texts"]]
        val_y = [int(y) for y in data["val_labels"]]
        return {
            "existing_model": _metrics(val_y, baseline.predict(val_x)),
            "expanded_candidate": _metrics(val_y, candidate.predict(val_x)),
        }

    message_validation = evaluate_validation(message_split)
    ad_x = [preprocess_text(t) for t in ad_split["val_texts"]]
    ad_y = [int(y) for y in ad_split["val_labels"]]
    ad_validation = {
        "grouped_ad_only_reference": _metrics(ad_y, ad_reference.predict(ad_x)),
        "expanded_candidate": _metrics(ad_y, candidate.predict(ad_x)),
    }
    # The candidate must improve both external-message and in-domain ad
    # validation. Otherwise added volume alone is not evidence of better ad
    # detection, even if the message score rises sharply.
    msg_base = message_validation["existing_model"]
    msg_new = message_validation["expanded_candidate"]
    ad_base = ad_validation["grouped_ad_only_reference"]
    ad_new = ad_validation["expanded_candidate"]
    message_improved = (msg_new["f1_macro"], msg_new["recall_by_class"]["High Risk"]) > (
        msg_base["f1_macro"], msg_base["recall_by_class"]["High Risk"]
    )
    ad_improved = (ad_new["f1_macro"], ad_new["recall_by_class"]["High Risk"]) > (
        ad_base["f1_macro"], ad_base["recall_by_class"]["High Risk"]
    )
    promoted = message_improved and ad_improved
    selected = candidate if promoted else baseline
    selected_name = EXPANDED_MODEL_PATH.name if promoted else MODEL_PATH.name
    model_version = "tfidf-logreg-expanded-v2" if promoted else "tfidf-logreg-v1.0"

    # The test set is opened for metrics only after candidate selection.
    def evaluate_test(data: dict[str, Any], test_model: Pipeline) -> dict[str, Any]:
        test_x = [preprocess_text(t) for t in data["test_texts"]]
        test_y = [int(y) for y in data["test_labels"]]
        return _metrics(test_y, test_model.predict(test_x))

    # Held-out test labels are first used only after the single candidate has
    # been selected using validation criteria above.
    message_test_metrics = evaluate_test(message_split, selected)
    ad_test_metrics = evaluate_test(ad_split, candidate) if promoted else None

    candidate.tracefin_model_version = "tfidf-logreg-expanded-v2"
    joblib.dump(candidate, EXPANDED_MODEL_PATH)
    if promoted:
        MODEL_SELECTION_PATH.write_text(json.dumps({
            "selected_model": EXPANDED_MODEL_PATH.name,
            "selected_metrics": EXPANDED_METRICS_PATH.name,
            "selection_metric": "improve grouped validation macro F1, then High Risk recall, on both domains",
            "validation_source": "grouped financial-ad and Mendeley manually labelled message splits",
        }, indent=2) + "\n", encoding="utf-8")
    else:
        # Keep a prior expanded choice from being silently superseded when a
        # newly trained candidate fails validation selection.
        MODEL_SELECTION_PATH.unlink(missing_ok=True)

    metrics = {
        "model_version": model_version,
        "algorithm": "TF-IDF (1,2-grams) + LogisticRegression",
        "selected_model": selected_name,
        "expanded_candidate_promoted": promoted,
        "task_scope": "financial scam messages, not representative financial advertisements",
        "validation_candidate_comparison": {
            "financial_advertisements": ad_validation,
            "manually_labelled_scam_messages": message_validation,
        },
        "selected_model_heldout_test": {
            "financial_advertisements": ad_test_metrics,
            "manually_labelled_scam_messages": message_test_metrics,
        },
        "test_metric_caveat": (
            "The legacy model's stored metrics reflect a random 400/100 row split over eight ad templates. "
            "Its ad test scores are not reported as leakage-free. Candidate ad test evaluation is withheld "
            "because it did not pass validation selection."
        ),
        "split_counts": {
            "train": len(training),
            "financial_ad_validation": len(ad_split["val_labels"]),
            "financial_ad_test": len(ad_split["test_labels"]),
            "message_validation": len(message_split["val_labels"]),
            "message_test": len(message_split["test_labels"]),
        },
        "train_class_distribution": {
            "Safe": int((training["label"] == 0).sum()),
            "High Risk": int((training["label"] == 1).sum()),
        },
        "train_source_counts": dict(Counter(training["source"])),
        "data_quality": data_quality,
        "training_quality": {
            "source_rows_before_filters": pre_quality_source_counts,
            "heldout_exact_text_overlaps_removed": overlap_rows_removed,
            "conflicting_label_text_rows_removed": conflicting_rows_removed,
            "exact_duplicate_rows_removed": exact_duplicate_rows_removed,
            "empty_text_rows_removed": empty_text_rows_removed,
        },
        "limitations": [
            "The Indian corpus is a mixture of real and augmented examples without row-level provenance.",
            "Both public corpora contain scam messages, not representative financial advertisements.",
            "The manually labelled message corpus is still not representative financial-ad data; the 500-row ad set has only eight template groups.",
            "The existing DistilBERT checkpoint and text/rule scoring logic are unchanged.",
        ],
    }
    EXPANDED_METRICS_PATH.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metrics, indent=2))
    return metrics


if __name__ == "__main__":
    main()
