"""
TRACE//FIN — Hugging Face DistilBERT Detection Module (Phase 4)
Fine-tuning and inference for suspicious financial advertisement classification.
Uses distilbert/distilbert-base-uncased as the base model.

This module is importable even when torch/transformers are not installed;
all heavy imports are guarded inside functions.
"""

import json
import logging
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import pandas as pd

from config import DATASET_PATH, MODELS_DIR, PROJECT_ROOT

logger = logging.getLogger("tracefin.hf")

# ── Paths & Constants ──────────────────────────────────────────────────
HF_MODEL_DIR = MODELS_DIR / "hf_financial_ad_classifier"
HF_METADATA_PATH = HF_MODEL_DIR / "metadata.json"
HF_BASE_MODEL = "distilbert/distilbert-base-uncased"
HF_MODEL_VERSION = "distilbert-v1.0"
HF_PREPROCESSING_VERSION = "ad-pii-normalization-v1"
HF_TASK_DEFINITION = "binary legitimate vs suspicious financial advertisement classification"
HF_MAX_LENGTH = 128

# Label mapping — binary classification
LABEL_MAP = {0: "Safe", 1: "High Risk"}
ID2LABEL = {0: "Safe", 1: "High Risk"}
LABEL2ID = {"Safe": 0, "High Risk": 1}

# Columns that must NEVER be used as features
EXCLUDED_COLUMNS = ["ID_No", "Account_Holder_Name", "Bank_Account_No", "IFSC_Code"]

# ── Cached Model State ─────────────────────────────────────────────────
_CACHED_HF_MODEL = None
_CACHED_HF_TOKENIZER = None
_CACHED_HF_MODEL_DIR: Optional[Path] = None
_CACHED_HF_DEVICE = None


def check_hf_dependencies() -> Dict[str, Any]:
    """Check whether torch and transformers are installed and report device info."""
    result = {
        "available": False,
        "torch_available": False,
        "transformers_available": False,
        "cuda_available": False,
        "device": "cpu",
        "errors": [],
    }

    try:
        import torch
        result["torch_available"] = True
        result["cuda_available"] = torch.cuda.is_available()
        result["device"] = "cuda" if torch.cuda.is_available() else "cpu"
    except ImportError:
        result["errors"].append("torch is not installed. Install with: pip install torch")

    try:
        import transformers  # noqa: F401
        result["transformers_available"] = True
    except ImportError:
        result["errors"].append("transformers is not installed. Install with: pip install transformers")

    result["available"] = result["torch_available"] and result["transformers_available"]
    return result


def _extract_template_fingerprint(text: str, pii_values: Optional[List[str]] = None) -> str:
    """
    Extract a fingerprint for near-duplicate / template detection.
    Uses the first 35 characters after lowercasing and stripping identifiers.
    This groups synthetic records from the same template together.
    """
    if not isinstance(text, str):
        return ""
    # Remove identifiers before grouping. These values are only used to make
    # split groups; they are never returned as features or passed to a model.
    cleaned = re.sub(r"\b\d{4,}\b", "", text)
    cleaned = re.sub(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", "", cleaned, flags=re.IGNORECASE)
    for value in pii_values or []:
        value = str(value).strip()
        if value and value.lower() != "nan":
            cleaned = re.sub(re.escape(value), " <PERSON> ", cleaned, flags=re.IGNORECASE)
    cleaned = " ".join(cleaned.lower().split())
    return cleaned[:35]


def _normalize_ad_text(text: str, pii_values: Optional[List[str]] = None) -> str:
    """Remove known personal/banking identifiers consistently at train and inference."""
    if not isinstance(text, str):
        return ""
    cleaned = text
    for value in pii_values or []:
        value = str(value).strip()
        if value and value.lower() != "nan":
            cleaned = re.sub(re.escape(value), "<PERSON>", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", " <IFSC_CODE> ", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\b\d{4,}\b", " <ACCOUNT_NUM> ", cleaned)
    return " ".join(cleaned.split())


def prepare_dataset(
    dataset_path: Path = DATASET_PATH,
    test_size: float = 0.2,
    val_size: float = 0.1,
    random_state: int = 42,
) -> Dict[str, Any]:
    """
    Load and split the financial advertisement dataset with grouped template splitting.

    Uses Advertisement_Text and Risk_Label only. NEVER uses PII columns.
    Groups near-identical templates to prevent leakage across partitions.

    Returns:
        dict with train/val/test texts and labels, label_map, class_distribution,
        template_count, and warnings.
    """
    import numpy as np

    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found at: {dataset_path}")

    df = pd.read_csv(dataset_path)

    # Validate schema
    for col in ["Advertisement_Text", "Risk_Label"]:
        if col not in df.columns:
            raise ValueError(f"Required column '{col}' missing from dataset")

    # Verify excluded columns are not used
    for col in EXCLUDED_COLUMNS:
        if col in df.columns:
            logger.info("Enforcing exclusion of identifier column: %s", col)

    # Map labels
    unrecognized = set(df["Risk_Label"].unique()) - set(LABEL2ID.keys())
    if unrecognized:
        raise ValueError(f"Unrecognized labels: {unrecognized}")

    texts = df["Advertisement_Text"].astype(str).tolist()
    labels = df["Risk_Label"].map(LABEL2ID).tolist()

    # Holder names are excluded from model features. If present within the ad
    # text, redact them only for fingerprinting so name variants of a template
    # stay in one partition and names do not survive in split keys.
    holder_names = (
        df["Account_Holder_Name"].fillna("").astype(str).tolist()
        if "Account_Holder_Name" in df.columns else [""] * len(texts)
    )
    # Identifiers embedded in Advertisement_Text are not excluded merely by
    # dropping their source columns. Redact known holder names from model input
    # as well as from template keys to prevent identity memorization.
    model_texts = [
        _normalize_ad_text(text, [name])
        for text, name in zip(texts, holder_names)
    ]
    fingerprints = [
        _extract_template_fingerprint(text, [name])
        for text, name in zip(texts, holder_names)
    ]
    df_work = pd.DataFrame({
        "text": model_texts,
        "label": labels,
        "fingerprint": fingerprints,
    })

    unique_templates = df_work["fingerprint"].unique()
    template_count = len(unique_templates)

    warnings = []
    if template_count < 10:
        warnings.append(
            f"Only {template_count} unique text templates detected. "
            "Model generalization will be severely limited."
        )
    if len(df) < 100:
        warnings.append(f"Dataset has only {len(df)} samples. Results may not be reliable.")

    # Grouped split: assign templates to partitions, not individual rows
    np.random.seed(random_state)
    template_labels = {}
    mixed_label_templates = []
    for fp in unique_templates:
        subset = df_work[df_work["fingerprint"] == fp]
        if subset["label"].nunique() > 1:
            mixed_label_templates.append(fp)
        template_labels[fp] = int(subset["label"].mode().iloc[0])

    template_df = pd.DataFrame([
        {"fingerprint": fp, "label": lbl}
        for fp, lbl in template_labels.items()
    ])

    # Stratify groups, not individual rows. A global group shuffle previously
    # put every validation example in one class for this dataset.
    test_templates: set[str] = set()
    val_templates: set[str] = set()
    train_templates: set[str] = set()
    used_row_split = False
    enough_groups_per_class = all(
        sum(label == class_id for label in template_labels.values()) >= 3
        for class_id in LABEL_MAP.keys()
    )

    if not mixed_label_templates and enough_groups_per_class:
        rng = np.random.default_rng(random_state)
        for class_id in LABEL_MAP.keys():
            class_groups = [fp for fp, label in template_labels.items() if label == class_id]
            shuffled = list(rng.permutation(class_groups))
            n_test = max(1, int(len(shuffled) * test_size))
            n_val = max(1, int(len(shuffled) * val_size))
            if n_test + n_val >= len(shuffled):
                enough_groups_per_class = False
                break
            test_templates.update(shuffled[:n_test])
            val_templates.update(shuffled[n_test:n_test + n_val])
            train_templates.update(shuffled[n_test + n_val:])

    if not enough_groups_per_class or mixed_label_templates:
        reason = (
            "Template fingerprints contain mixed labels."
            if mixed_label_templates else
            "At least one class has too few templates for all three partitions."
        )
        warnings.append(reason + " Falling back to a grouped, non-stratified split; inspect class support before training.")
        template_df = template_df.sample(frac=1, random_state=random_state).reset_index(drop=True)
        n_templates = len(template_df)
        n_test = max(1, int(n_templates * test_size))
        n_val = max(1, int(n_templates * val_size))

        if n_test + n_val >= n_templates:
            warnings.append("Too few templates; falling back to a random row split with possible template leakage.")
            used_row_split = True
            indices = np.arange(len(df_work))
            np.random.default_rng(random_state).shuffle(indices)
            n_test_rows = max(1, int(len(df_work) * test_size))
            n_val_rows = max(1, int(len(df_work) * val_size))
            test_idx = indices[:n_test_rows]
            val_idx = indices[n_test_rows:n_test_rows + n_val_rows]
            train_idx = indices[n_test_rows + n_val_rows:]
            train_texts = [df_work.iloc[i]["text"] for i in train_idx]
            train_labels = [df_work.iloc[i]["label"] for i in train_idx]
            val_texts = [df_work.iloc[i]["text"] for i in val_idx]
            val_labels = [df_work.iloc[i]["label"] for i in val_idx]
            test_texts = [df_work.iloc[i]["text"] for i in test_idx]
            test_labels = [df_work.iloc[i]["label"] for i in test_idx]
        else:
            test_templates = set(template_df.iloc[:n_test]["fingerprint"])
            val_templates = set(template_df.iloc[n_test:n_test + n_val]["fingerprint"])
            train_templates = set(template_df.iloc[n_test + n_val:]["fingerprint"])

    if not used_row_split:
        train_mask = df_work["fingerprint"].isin(train_templates)
        val_mask = df_work["fingerprint"].isin(val_templates)
        test_mask = df_work["fingerprint"].isin(test_templates)
        train_texts = df_work[train_mask]["text"].tolist()
        train_labels = df_work[train_mask]["label"].tolist()
        val_texts = df_work[val_mask]["text"].tolist()
        val_labels = df_work[val_mask]["label"].tolist()
        test_texts = df_work[test_mask]["text"].tolist()
        test_labels = df_work[test_mask]["label"].tolist()

    class_dist = {
        "total": {"Safe": labels.count(0), "High Risk": labels.count(1)},
        "train": {"Safe": train_labels.count(0), "High Risk": train_labels.count(1)},
        "val": {"Safe": val_labels.count(0), "High Risk": val_labels.count(1)},
        "test": {"Safe": test_labels.count(0), "High Risk": test_labels.count(1)},
    }

    return {
        "train_texts": train_texts,
        "train_labels": train_labels,
        "val_texts": val_texts,
        "val_labels": val_labels,
        "test_texts": test_texts,
        "test_labels": test_labels,
        "label_map": LABEL_MAP,
        "class_distribution": class_dist,
        "template_count": template_count,
        "template_groups": {
            split_name: sorted(set(df_work.loc[
                df_work["text"].isin(values), "fingerprint"
            ]))
            for split_name, values in (
                ("train", train_texts), ("val", val_texts), ("test", test_texts)
            )
        },
        "warnings": warnings,
    }


def train_distilbert(
    train_texts: List[str],
    train_labels: List[int],
    val_texts: List[str],
    val_labels: List[int],
    epochs: int = 3,
    batch_size: int = 8,
    learning_rate: float = 2e-5,
    max_length: int = 128,
    seed: int = 42,
    device: Optional[str] = None,
    progress_callback: Optional[Callable] = None,
) -> Dict[str, Any]:
    """
    Fine-tune distilbert-base-uncased for binary classification.

    Uses a simple PyTorch training loop (no HuggingFace Trainer dependency).
    Saves model + tokenizer + metadata to HF_MODEL_DIR.
    Backs up existing model directory before overwriting.

    Args:
        progress_callback: Optional callback(epoch, total_epochs, train_loss, val_loss)

    Returns:
        dict with success, model_dir, epochs_completed, losses, accuracy, error
    """
    try:
        import torch
        from torch.utils.data import DataLoader, TensorDataset
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError as exc:
        return {
            "success": False,
            "model_dir": None,
            "epochs_completed": 0,
            "final_train_loss": None,
            "final_val_loss": None,
            "val_accuracy": None,
            "error": f"Missing dependencies: {exc}",
        }

    # Set seeds for reproducibility
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)

    # Determine device
    if device is None:
        device = "cuda" if torch.cuda.is_available() else "cpu"
    dev = torch.device(device)

    try:
        # Load tokenizer and model
        tokenizer = AutoTokenizer.from_pretrained(HF_BASE_MODEL)
        model = AutoModelForSequenceClassification.from_pretrained(
            HF_BASE_MODEL,
            num_labels=2,
            id2label=ID2LABEL,
            label2id=LABEL2ID,
        )
        model.to(dev)

        # Tokenize
        train_enc = tokenizer(
            train_texts, padding=True, truncation=True,
            max_length=max_length, return_tensors="pt",
        )
        val_enc = tokenizer(
            val_texts, padding=True, truncation=True,
            max_length=max_length, return_tensors="pt",
        )

        train_dataset = TensorDataset(
            train_enc["input_ids"], train_enc["attention_mask"],
            torch.tensor(train_labels, dtype=torch.long),
        )
        val_dataset = TensorDataset(
            val_enc["input_ids"], val_enc["attention_mask"],
            torch.tensor(val_labels, dtype=torch.long),
        )

        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=batch_size)

        # Optimizer
        optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate)

        # Training loop
        final_train_loss = 0.0
        final_val_loss = 0.0
        val_accuracy = 0.0
        epochs_completed = 0

        for epoch in range(epochs):
            # Train
            model.train()
            total_loss = 0.0
            for batch in train_loader:
                ids, mask, lbls = [b.to(dev) for b in batch]
                optimizer.zero_grad()
                outputs = model(input_ids=ids, attention_mask=mask, labels=lbls)
                loss = outputs.loss
                loss.backward()
                optimizer.step()
                total_loss += loss.item()

            avg_train_loss = total_loss / len(train_loader) if train_loader else 0.0

            # Validate
            model.eval()
            val_loss_total = 0.0
            correct = 0
            total = 0
            with torch.no_grad():
                for batch in val_loader:
                    ids, mask, lbls = [b.to(dev) for b in batch]
                    outputs = model(input_ids=ids, attention_mask=mask, labels=lbls)
                    val_loss_total += outputs.loss.item()
                    preds = outputs.logits.argmax(dim=-1)
                    correct += (preds == lbls).sum().item()
                    total += lbls.size(0)

            avg_val_loss = val_loss_total / len(val_loader) if val_loader else 0.0
            val_acc = correct / total if total > 0 else 0.0

            final_train_loss = avg_train_loss
            final_val_loss = avg_val_loss
            val_accuracy = val_acc
            epochs_completed = epoch + 1

            logger.info(
                "Epoch %d/%d — train_loss: %.4f, val_loss: %.4f, val_acc: %.4f",
                epoch + 1, epochs, avg_train_loss, avg_val_loss, val_acc,
            )

            if progress_callback:
                progress_callback(epoch + 1, epochs, avg_train_loss, avg_val_loss)

        # Backup existing model dir
        if HF_MODEL_DIR.exists():
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            backup_dir = HF_MODEL_DIR.parent / f"hf_financial_ad_classifier_backup_{ts}"
            try:
                shutil.move(str(HF_MODEL_DIR), str(backup_dir))
                logger.info("Backed up previous model to: %s", backup_dir)
            except Exception as bk_err:
                logger.warning("Could not backup previous model: %s", bk_err)

        # Save model and tokenizer
        HF_MODEL_DIR.mkdir(parents=True, exist_ok=True)
        model.save_pretrained(str(HF_MODEL_DIR))
        tokenizer.save_pretrained(str(HF_MODEL_DIR))

        # Save metadata
        metadata = {
            "base_model": HF_BASE_MODEL,
            "model_version": HF_MODEL_VERSION,
            "preprocessing_version": HF_PREPROCESSING_VERSION,
            "task_definition": HF_TASK_DEFINITION,
            "label_map": LABEL_MAP,
            "id2label": ID2LABEL,
            "label2id": LABEL2ID,
            "training_config": {
                "epochs": epochs,
                "batch_size": batch_size,
                "learning_rate": learning_rate,
                "max_length": max_length,
                "seed": seed,
                "device": device,
                "train_samples": len(train_texts),
                "val_samples": len(val_texts),
            },
            "training_results": {
                "epochs_completed": epochs_completed,
                "final_train_loss": round(final_train_loss, 6),
                "final_val_loss": round(final_val_loss, 6),
                "val_accuracy": round(val_accuracy, 6),
            },
            "trained_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(HF_METADATA_PATH, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        logger.info("Saved fine-tuned model to: %s", HF_MODEL_DIR)

        return {
            "success": True,
            "model_dir": str(HF_MODEL_DIR),
            "epochs_completed": epochs_completed,
            "final_train_loss": round(final_train_loss, 6),
            "final_val_loss": round(final_val_loss, 6),
            "val_accuracy": round(val_accuracy, 6),
            "error": None,
        }

    except RuntimeError as exc:
        if "out of memory" in str(exc).lower():
            return {
                "success": False,
                "model_dir": None,
                "epochs_completed": 0,
                "final_train_loss": None,
                "final_val_loss": None,
                "val_accuracy": None,
                "error": f"Out of memory: {exc}. Try reducing batch_size or max_length.",
            }
        return {
            "success": False,
            "model_dir": None,
            "epochs_completed": 0,
            "final_train_loss": None,
            "final_val_loss": None,
            "val_accuracy": None,
            "error": f"Training error: {exc}",
        }
    except Exception as exc:
        return {
            "success": False,
            "model_dir": None,
            "epochs_completed": 0,
            "final_train_loss": None,
            "final_val_loss": None,
            "val_accuracy": None,
            "error": f"Unexpected error: {exc}",
        }


def evaluate_distilbert(
    test_texts: List[str],
    test_labels: List[int],
    device: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Evaluate a fine-tuned DistilBERT model on a test set.

    Returns:
        dict with accuracy, precision, recall, f1 scores, confusion_matrix,
        per_class metrics, test_count, model_version
    """
    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        from sklearn.metrics import (
            accuracy_score, classification_report, confusion_matrix,
            precision_score, recall_score, f1_score,
        )
    except ImportError as exc:
        return {"error": f"Missing dependencies: {exc}"}

    if not HF_MODEL_DIR.exists():
        return {"error": f"No trained model found at {HF_MODEL_DIR}"}

    if device is None:
        device = "cuda" if torch.cuda.is_available() else "cpu"
    dev = torch.device(device)

    try:
        tokenizer = AutoTokenizer.from_pretrained(str(HF_MODEL_DIR))
        model = AutoModelForSequenceClassification.from_pretrained(str(HF_MODEL_DIR))
        model.to(dev)
        model.eval()

        # Batch predict
        all_preds = []
        batch_size = 16
        for i in range(0, len(test_texts), batch_size):
            batch_texts = test_texts[i:i + batch_size]
            enc = tokenizer(
                batch_texts, padding=True, truncation=True,
                max_length=128, return_tensors="pt",
            )
            enc = {k: v.to(dev) for k, v in enc.items()}

            with torch.no_grad():
                outputs = model(**enc)
                preds = outputs.logits.argmax(dim=-1).cpu().tolist()
                all_preds.extend(preds)

        # Calculate metrics
        acc = accuracy_score(test_labels, all_preds)
        report = classification_report(
            test_labels, all_preds,
            target_names=["Safe", "High Risk"],
            output_dict=True,
            zero_division=0,
        )
        cm = confusion_matrix(test_labels, all_preds).tolist()

        result = {
            "accuracy": round(float(acc), 4),
            "precision": round(float(precision_score(test_labels, all_preds, zero_division=0)), 4),
            "recall": round(float(recall_score(test_labels, all_preds, zero_division=0)), 4),
            "macro_f1": round(float(f1_score(test_labels, all_preds, average="macro", zero_division=0)), 4),
            "weighted_f1": round(float(f1_score(test_labels, all_preds, average="weighted", zero_division=0)), 4),
            "confusion_matrix": cm,
            "per_class": {
                "Safe": {
                    "precision": round(report["Safe"]["precision"], 4),
                    "recall": round(report["Safe"]["recall"], 4),
                    "f1": round(report["Safe"]["f1-score"], 4),
                    "support": int(report["Safe"]["support"]),
                },
                "High Risk": {
                    "precision": round(report["High Risk"]["precision"], 4),
                    "recall": round(report["High Risk"]["recall"], 4),
                    "f1": round(report["High Risk"]["f1-score"], 4),
                    "support": int(report["High Risk"]["support"]),
                },
            },
            "test_count": len(test_labels),
            "model_version": HF_MODEL_VERSION,
            "error": None,
        }

        # Update metadata with evaluation results
        if HF_METADATA_PATH.exists():
            try:
                with open(HF_METADATA_PATH, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                meta["evaluation_metrics"] = result
                meta["evaluated_at"] = datetime.now(timezone.utc).isoformat()
                with open(HF_METADATA_PATH, "w", encoding="utf-8") as f:
                    json.dump(meta, f, indent=2)
            except Exception:
                pass

        return result

    except Exception as exc:
        return {"error": f"Evaluation error: {exc}"}


def predict_ad_hf(text: str) -> Dict[str, Any]:
    """
    Run DistilBERT inference on advertisement text.

    Caches the model and tokenizer in module-level globals keyed by path.

    Returns:
        dict with available, risk_label, prediction, confidence, confidence_pct,
        model_version, error, disclaimer
    """
    global _CACHED_HF_MODEL, _CACHED_HF_TOKENIZER, _CACHED_HF_MODEL_DIR, _CACHED_HF_DEVICE

    base_result = {
        "available": False,
        "risk_label": None,
        "prediction": None,
        "confidence": None,
        "confidence_pct": None,
        "class_probabilities": None,
        "high_risk_score": None,
        "token_count": None,
        "max_length": HF_MAX_LENGTH,
        "model_version": HF_MODEL_VERSION,
        "error": None,
        "disclaimer": (
            "DistilBERT predictions are fine-tuned on a small synthetic dataset. "
            "Scores reflect model confidence within the training distribution, "
            "not calibrated real-world probabilities. Human review is required."
        ),
    }

    if not text or not text.strip():
        base_result["error"] = "Input text is empty."
        return base_result

    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError as exc:
        base_result["error"] = f"Missing dependencies: {exc}"
        return base_result

    if not HF_MODEL_DIR.exists():
        base_result["error"] = "DistilBERT model not found. Train the model first."
        return base_result

    try:
        # Load or use cached model
        if _CACHED_HF_MODEL is None or _CACHED_HF_MODEL_DIR != HF_MODEL_DIR:
            _CACHED_HF_TOKENIZER = AutoTokenizer.from_pretrained(str(HF_MODEL_DIR))
            _CACHED_HF_MODEL = AutoModelForSequenceClassification.from_pretrained(
                str(HF_MODEL_DIR)
            )
            actual_id2label = {
                str(k): str(v) for k, v in _CACHED_HF_MODEL.config.id2label.items()
            }
            if actual_id2label != {"0": "Safe", "1": "High Risk"}:
                raise ValueError(f"Checkpoint label mapping mismatch: {actual_id2label}")
            if int(_CACHED_HF_MODEL.config.num_labels) != len(LABEL_MAP):
                raise ValueError(
                    f"Checkpoint has {_CACHED_HF_MODEL.config.num_labels} classes; expected {len(LABEL_MAP)}"
                )
            device = "cuda" if torch.cuda.is_available() else "cpu"
            _CACHED_HF_MODEL.to(torch.device(device))
            _CACHED_HF_MODEL.eval()
            _CACHED_HF_MODEL_DIR = HF_MODEL_DIR
            _CACHED_HF_DEVICE = device

        metadata = get_hf_model_info() or {}
        inference_text = text.strip()
        if metadata.get("preprocessing_version") == HF_PREPROCESSING_VERSION:
            inference_text = _normalize_ad_text(inference_text)
        enc = _CACHED_HF_TOKENIZER(
            inference_text, padding=True, truncation=True,
            max_length=HF_MAX_LENGTH, return_tensors="pt",
        )
        enc = {k: v.to(torch.device(_CACHED_HF_DEVICE)) for k, v in enc.items()}

        with torch.no_grad():
            outputs = _CACHED_HF_MODEL(**enc)
            if outputs.logits.shape[-1] != len(LABEL_MAP):
                raise ValueError(f"Model returned {outputs.logits.shape[-1]} classes; expected {len(LABEL_MAP)}")
            probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
            pred_class = probs.argmax(dim=-1).item()
            confidence = probs[0][pred_class].item()

        risk_label = LABEL_MAP.get(pred_class, "Unknown")

        base_result.update({
            "available": True,
            "risk_label": risk_label,
            "prediction": pred_class,
            "confidence": round(confidence, 4),
            "confidence_pct": round(confidence * 100, 1),
            "class_probabilities": {
                LABEL_MAP[index]: round(float(probs[0][index].item()), 4)
                for index in range(len(LABEL_MAP))
            },
            "high_risk_score": round(float(probs[0][LABEL2ID["High Risk"]].item()), 4),
            "token_count": int(enc["input_ids"].shape[-1]),
        })
        return base_result

    except Exception as exc:
        base_result["error"] = f"Inference error: {exc}"
        return base_result


def get_hf_model_info() -> Optional[Dict[str, Any]]:
    """Read metadata.json from HF_MODEL_DIR if it exists."""
    if not HF_METADATA_PATH.exists():
        return None
    try:
        with open(HF_METADATA_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        logger.error("Failed to read HF metadata: %s", exc)
        return None


def get_hf_model_status() -> Dict[str, Any]:
    """Report checkpoint readiness and training evidence without running inference."""
    metadata = get_hf_model_info() or {}
    config_path = HF_MODEL_DIR / "config.json"
    config_data: Dict[str, Any] = {}
    try:
        if config_path.is_file():
            with open(config_path, "r", encoding="utf-8") as f:
                config_data = json.load(f)
    except Exception as exc:
        return {
            "available": False,
            "trained": False,
            "loaded": False,
            "model_version": None,
            "error": f"Cannot read local model config: {exc}",
        }

    has_weights = any((HF_MODEL_DIR / name).is_file() for name in ("model.safetensors", "pytorch_model.bin"))
    has_tokenizer = any((HF_MODEL_DIR / name).is_file() for name in ("tokenizer.json", "vocab.txt"))
    expected_id2label = {"0": "Safe", "1": "High Risk"}
    actual_id2label = {str(k): str(v) for k, v in (config_data.get("id2label") or {}).items()}
    label_mapping_valid = actual_id2label == expected_id2label
    has_training_record = bool(
        metadata.get("trained_at")
        and metadata.get("training_config")
        and metadata.get("training_results")
        and metadata.get("base_model")
    )
    trained_for_scam_ads = metadata.get("task_definition") == HF_TASK_DEFINITION
    deps_available = (
        __import__("importlib.util", fromlist=["find_spec"]).find_spec("torch") is not None
        and __import__("importlib.util", fromlist=["find_spec"]).find_spec("transformers") is not None
    )
    loaded = _CACHED_HF_MODEL is not None and _CACHED_HF_MODEL_DIR == HF_MODEL_DIR
    artifact_complete = config_path.is_file() and has_weights and has_tokenizer and label_mapping_valid
    available = artifact_complete and deps_available

    if loaded and has_training_record and trained_for_scam_ads:
        status = "loaded · scam-ad fine-tuned"
    elif loaded and has_training_record:
        status = "loaded · fine-tuning task unverified"
    elif loaded:
        status = "loaded · fine-tuning unverified"
    elif not artifact_complete:
        status = "unavailable"
    elif not deps_available:
        status = "dependencies missing"
    elif has_training_record and trained_for_scam_ads:
        status = "fine-tuned for scam-ad classification"
    elif has_training_record:
        status = "fine-tuned; task provenance unverified"
    else:
        status = "checkpoint present; fine-tuning unverified"

    errors = []
    if not has_weights:
        errors.append("model weight file is missing")
    if not has_tokenizer:
        errors.append("tokenizer files are missing")
    if config_path.is_file() and not label_mapping_valid:
        errors.append("checkpoint labels do not match Safe=0 / High Risk=1")
    if not deps_available:
        errors.append("torch and transformers are required for inference")
    if artifact_complete and not has_training_record:
        errors.append("training metadata is missing; fine-tuning status cannot be verified")

    return {
        "available": available,
        "trained": has_training_record and label_mapping_valid,
        "trained_for_scam_ads": has_training_record and trained_for_scam_ads and label_mapping_valid,
        "task_definition": metadata.get("task_definition"),
        "loaded": loaded,
        "status": status,
        "model_version": metadata.get("model_version") if has_training_record else None,
        "base_model": metadata.get("base_model"),
        "trained_at": metadata.get("trained_at"),
        "label_mapping_valid": label_mapping_valid,
        "error": "; ".join(errors) if errors else None,
    }
