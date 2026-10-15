#!/usr/bin/env python3
"""Compare scam-ad classifiers on one grouped train/validation/test split.

The held-out test set is not passed to training or model selection. Transformer
checkpoints and reports are kept under /tmp; project artifacts are untouched.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from config import DATASET_PATH
from src.hf_model import HF_BASE_MODEL, _extract_template_fingerprint, _normalize_ad_text, prepare_dataset
from src.ml_model import preprocess_text


def score(labels: list[int], preds: list[int]) -> dict[str, Any]:
    cm = confusion_matrix(labels, preds, labels=[0, 1])
    fn = int(cm[1][0])
    positives = int(cm[1].sum())
    return {
        "accuracy": round(float(accuracy_score(labels, preds)), 4),
        "precision_high_risk": round(float(precision_score(labels, preds, pos_label=1, zero_division=0)), 4),
        "recall_high_risk": round(float(recall_score(labels, preds, pos_label=1, zero_division=0)), 4),
        "f1_high_risk": round(float(f1_score(labels, preds, pos_label=1, zero_division=0)), 4),
        "macro_f1": round(float(f1_score(labels, preds, average="macro", zero_division=0)), 4),
        "false_negative_rate": round(fn / positives, 4) if positives else None,
        "confusion_matrix_actual_rows_predicted_columns_safe_high": cm.tolist(),
        "support": {"Safe": int(cm[0].sum()), "High Risk": positives},
    }


def train_transformer(
    model_name: str,
    train_texts: list[str],
    train_labels: list[int],
    val_texts: list[str],
    val_labels: list[int],
    *,
    epochs: int,
    batch_size: int,
    max_length: int,
    device: str,
    train_encoder: bool,
) -> tuple[Any, Any, dict[str, Any]]:
    import torch
    from torch.utils.data import DataLoader, TensorDataset
    from transformers import AutoConfig, AutoModelForSequenceClassification, AutoTokenizer

    labels = {0: "Safe", 1: "High Risk"}
    label_ids = {v: k for k, v in labels.items()}
    tokenizer = AutoTokenizer.from_pretrained(model_name, local_files_only=True)
    config = AutoConfig.from_pretrained(model_name, local_files_only=True)
    config.num_labels = 2
    config.id2label = labels
    config.label2id = label_ids
    model = AutoModelForSequenceClassification.from_pretrained(
        model_name,
        config=config,
        ignore_mismatched_sizes=True,
        local_files_only=True,
    )
    if {str(k): v for k, v in model.config.id2label.items()} != {"0": "Safe", "1": "High Risk"}:
        raise ValueError(f"Unexpected classifier label map for {model_name}: {model.config.id2label}")
    if not train_encoder:
        for parameter in model.base_model.parameters():
            parameter.requires_grad = False

    train_enc = tokenizer(train_texts, padding="max_length", truncation=True, max_length=max_length, return_tensors="pt")
    train_ds = TensorDataset(
        train_enc["input_ids"], train_enc["attention_mask"], torch.tensor(train_labels, dtype=torch.long)
    )
    val_enc = tokenizer(val_texts, padding="max_length", truncation=True, max_length=max_length, return_tensors="pt")
    val_ds = TensorDataset(
        val_enc["input_ids"], val_enc["attention_mask"], torch.tensor(val_labels, dtype=torch.long)
    )
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False)
    model.to(device)
    optimizer = torch.optim.AdamW((p for p in model.parameters() if p.requires_grad), lr=2e-5)
    best = {"macro_f1": -1.0, "recall_high_risk": -1.0, "epoch": 0}
    best_state = None

    for epoch in range(epochs):
        model.train()
        for batch in train_loader:
            ids, mask, y = [x.to(device) for x in batch]
            optimizer.zero_grad()
            out = model(input_ids=ids, attention_mask=mask, labels=y)
            out.loss.backward()
            optimizer.step()

        model.eval()
        preds = []
        with torch.no_grad():
            for ids, mask, _ in val_loader:
                logits = model(input_ids=ids.to(device), attention_mask=mask.to(device)).logits
                preds.extend(logits.argmax(dim=-1).cpu().tolist())
        current = score(val_labels, preds)
        rank = (current["macro_f1"], current["recall_high_risk"])
        if rank > (best["macro_f1"], best["recall_high_risk"]):
            best = {**current, "epoch": epoch + 1}
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}

    if best_state is None:
        raise RuntimeError(f"No validation checkpoint selected for {model_name}")
    model.load_state_dict(best_state)
    model.to(device)
    model.eval()
    return model, tokenizer, best


def predict_transformer(model: Any, tokenizer: Any, texts: list[str], max_length: int, device: str) -> list[int]:
    import torch

    preds = []
    for offset in range(0, len(texts), 16):
        batch = tokenizer(
            texts[offset:offset + 16],
            padding=True,
            truncation=True,
            max_length=max_length,
            return_tensors="pt",
        )
        with torch.no_grad():
            logits = model(
                input_ids=batch["input_ids"].to(device),
                attention_mask=batch["attention_mask"].to(device),
            ).logits
        preds.extend(logits.argmax(dim=-1).cpu().tolist())
    return preds


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DATASET_PATH)
    parser.add_argument("--finbert", type=Path, required=True, help="Local ProsusAI/finbert snapshot directory")
    parser.add_argument("--epochs", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--max-length", type=int, default=128)
    args = parser.parse_args()

    data = prepare_dataset(args.dataset, test_size=0.2, val_size=0.1, random_state=42)
    raw = pd.read_csv(args.dataset)
    holder_names = (
        raw["Account_Holder_Name"].fillna("").astype(str)
        if "Account_Holder_Name" in raw else pd.Series([""] * len(raw))
    )
    fingerprints = [
        _extract_template_fingerprint(text, [name])
        for text, name in zip(raw["Advertisement_Text"].astype(str), holder_names)
    ]
    template_labels = pd.DataFrame({"template": fingerprints, "label": raw["Risk_Label"]})
    train_texts = [_normalize_ad_text(t) for t in data["train_texts"]]
    val_texts = [_normalize_ad_text(t) for t in data["val_texts"]]
    test_texts = [_normalize_ad_text(t) for t in data["test_texts"]]
    y_train, y_val = data["train_labels"], data["val_labels"]

    report: dict[str, Any] = {
        "data_audit": {
            "rows": int(len(raw)),
            "class_counts": {str(k): int(v) for k, v in raw["Risk_Label"].value_counts().items()},
            "exact_text_duplicates": int(raw["Advertisement_Text"].duplicated(keep=False).sum()),
            "exact_texts_with_conflicting_labels": int(
                (raw.groupby("Advertisement_Text")["Risk_Label"].nunique() > 1).sum()
            ),
            "duplicate_record_ids": int(raw["ID_No"].duplicated(keep=False).sum()) if "ID_No" in raw else None,
            "normalized_template_count": int(template_labels["template"].nunique()),
            "templates_with_conflicting_labels": int(
                (template_labels.groupby("template")["label"].nunique() > 1).sum()
            ),
            "split_unit": "normalized text template, to keep variants in one partition",
        },
        "split": data["class_distribution"],
        "template_count": data["template_count"],
        "warnings": data["warnings"],
        "selection_metric": "validation macro F1; tie-breaker High Risk recall",
        "test_access": "held until validation selection is complete",
        "validation": {},
        "test": {},
    }
    candidates: dict[str, Any] = {}

    tfidf = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_df=0.98, sublinear_tf=True, stop_words="english")),
        ("clf", LogisticRegression(C=1.0, random_state=42, class_weight="balanced", max_iter=1000, solver="lbfgs")),
    ])
    tfidf.fit([preprocess_text(t) for t in train_texts], y_train)
    tfidf_val = tfidf.predict([preprocess_text(t) for t in val_texts]).tolist()
    candidates["TF-IDF + Logistic Regression"] = (score(y_val, tfidf_val), lambda: tfidf.predict([preprocess_text(t) for t in test_texts]).tolist())
    report["validation"]["TF-IDF + Logistic Regression"] = candidates["TF-IDF + Logistic Regression"][0]

    import torch
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model_refs = {
        "Fresh DistilBERT fine-tune": HF_BASE_MODEL,
        "ProsusAI/FinBERT fine-tuned for scam ads": str(args.finbert.resolve()),
    }
    for name, ref, train_encoder in (
        ("Fresh DistilBERT fine-tune", model_refs["Fresh DistilBERT fine-tune"], True),
        ("ProsusAI/FinBERT scam-ad head tuning", model_refs["ProsusAI/FinBERT fine-tuned for scam ads"], False),
    ):
        model, tokenizer, val_metrics = train_transformer(
            ref, train_texts, y_train, val_texts, y_val,
            epochs=args.epochs, batch_size=args.batch_size,
            max_length=args.max_length, device=device, train_encoder=train_encoder,
        )
        report["validation"][name] = val_metrics
        candidates[name] = (
            val_metrics,
            lambda m=model, t=tokenizer: predict_transformer(m, t, test_texts, args.max_length, device),
        )

    selected = max(
        candidates,
        key=lambda n: (candidates[n][0]["macro_f1"], candidates[n][0]["recall_high_risk"]),
    )
    report["selected_by_validation"] = selected

    # First access to held-out labels/predictions occurs after selection above.
    y_test = data["test_labels"]
    for name, (_, predict) in candidates.items():
        report["test"][name] = score(y_test, predict())
    report["runtime"] = {"device": device, "max_length": args.max_length, "truncation": True}
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
