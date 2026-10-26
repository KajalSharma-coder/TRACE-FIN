#!/usr/bin/env python3
"""
TRACE//FIN — Hugging Face DistilBERT Fine-Tuning CLI (Phase 4)
Fine-tunes distilbert/distilbert-base-uncased on data/back.dataset.csv.

Usage:
    python scripts/train_hf_model.py [--epochs 3] [--batch-size 8] [--lr 2e-5] [--max-length 128] [--seed 42] [--device cpu|cuda]

Safety guarantees:
    - Never uses PII or banking identifiers (ID_No, Account_Holder_Name, Bank_Account_No, IFSC_Code).
    - Grouped template splitting prevents near-identical synthetic phrasing from leaking across partitions.
    - Saves model artifacts to models/hf_financial_ad_classifier/.
    - Backs up previous model artifacts before overwriting.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config import DATASET_PATH, HF_MODEL_DIR, HF_METRICS_PATH
from src.hf_model import (
    check_hf_dependencies,
    prepare_dataset,
    train_distilbert,
    evaluate_distilbert,
    HF_BASE_MODEL,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("tracefin.train_hf")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Fine-tune DistilBERT for TRACE//FIN suspicious financial advertisement detection."
    )
    parser.add_argument("--epochs", type=int, default=3, help="Number of training epochs (default: 3)")
    parser.add_argument("--batch-size", type=int, default=8, help="Batch size (default: 8)")
    parser.add_argument("--lr", type=float, default=2e-5, help="Learning rate (default: 2e-5)")
    parser.add_argument("--max-length", type=int, default=128, help="Max token sequence length (default: 128)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility (default: 42)")
    parser.add_argument("--device", type=str, default=None, choices=["cpu", "cuda"], help="Compute device (default: auto)")
    parser.add_argument("--test-size", type=float, default=0.20, help="Held-out test split ratio (default: 0.20)")
    parser.add_argument("--val-size", type=float, default=0.10, help="Validation split ratio (default: 0.10)")
    parser.add_argument("--dataset-path", type=Path, default=DATASET_PATH, help=f"Path to dataset CSV (default: {DATASET_PATH})")
    return parser.parse_args()


def main():
    args = parse_args()
    print("=" * 70)
    print("  TRACE//FIN — Hugging Face DistilBERT Fine-Tuning Pipeline (Phase 4)")
    print("=" * 70)

    # 1. Dependency check
    deps = check_hf_dependencies()
    print(f"\n[1/5] Checking PyTorch and Hugging Face dependencies...")
    print(f"      • PyTorch installed:      {deps['torch_available']}")
    print(f"      • Transformers installed: {deps['transformers_available']}")
    print(f"      • CUDA acceleration:      {deps['cuda_available']}")
    print(f"      • Target Device:          {args.device or deps['device']}")

    if not deps["available"]:
        print("\n❌ Missing required dependencies:")
        for err in deps["errors"]:
            print(f"   • {err}")
        sys.exit(1)

    # 2. Dataset preparation with template grouping
    print(f"\n[2/5] Inspecting & preparing dataset: {args.dataset_path}")
    try:
        data = prepare_dataset(
            dataset_path=args.dataset_path,
            test_size=args.test_size,
            val_size=args.val_size,
            random_state=args.seed,
        )
    except Exception as exc:
        print(f"\n❌ Dataset preparation failed: {exc}")
        sys.exit(1)

    print(f"      • Total templates detected: {data['template_count']}")
    print(f"      • Total dataset split:")
    print(f"        - Training samples:       {len(data['train_texts'])} ({data['class_distribution']['train']})")
    print(f"        - Validation samples:     {len(data['val_texts'])} ({data['class_distribution']['val']})")
    print(f"        - Held-out test samples:  {len(data['test_texts'])} ({data['class_distribution']['test']})")

    if data["warnings"]:
        print("\n⚠️ Scientific Dataset Limitations / Warnings:")
        for w in data["warnings"]:
            print(f"   • {w}")

    if not data.get("training_ready"):
        print("\nTraining blocked: grouped dataset safeguards are not satisfied.")
        sys.exit(1)

    # 3. Model Training
    print(f"\n[3/5] Starting fine-tuning with base model: '{HF_BASE_MODEL}'...")
    print(f"      • Epochs: {args.epochs} | Batch size: {args.batch_size} | LR: {args.lr} | Max len: {args.max_length}")

    def progress_callback(epoch, total_epochs, train_loss, val_loss):
        print(f"      → Epoch {epoch}/{total_epochs} completed | Train Loss: {train_loss:.4f} | Val Loss: {val_loss:.4f}")

    train_res = train_distilbert(
        train_texts=data["train_texts"],
        train_labels=data["train_labels"],
        val_texts=data["val_texts"],
        val_labels=data["val_labels"],
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        max_length=args.max_length,
        seed=args.seed,
        device=args.device,
        progress_callback=progress_callback,
        dataset_metadata=data,
        test_texts=data["test_texts"],
        test_labels=data["test_labels"],
    )

    if not train_res["success"]:
        print(f"\n❌ Fine-tuning failed: {train_res['error']}")
        sys.exit(1)

    print(f"\n✓ Fine-tuning successful! Artifacts written to:")
    print(f"  {train_res['model_dir']}")
    print(f"  Final Validation Accuracy: {train_res['val_accuracy']*100:.2f}%")

    # 4. Re-check the exact promoted checkpoint. Failure is fatal.
    print(f"\n[4/5] Evaluating fine-tuned model on held-out test partition ({len(data['test_texts'])} samples)...")
    eval_res = evaluate_distilbert(
        test_texts=data["test_texts"],
        test_labels=data["test_labels"],
        device=args.device,
    )

    if eval_res.get("error"):
        sys.exit(1)
    else:
        print(f"      • Test Accuracy:     {eval_res['accuracy']*100:.2f}%")
        print(f"      • Macro F1-Score:    {eval_res['macro_f1']:.4f}")
        print(f"      • Weighted F1-Score: {eval_res['weighted_f1']:.4f}")
        print(f"      • Precision:         {eval_res['precision']:.4f}")
        print(f"      • Recall:            {eval_res['recall']:.4f}")
        print(f"      • Confusion Matrix:  {eval_res['confusion_matrix']}")
        print(f"      • Per-Class Performance:")
        for cls_name, cls_metrics in eval_res["per_class"].items():
            print(f"        - {cls_name:10s}: Precision={cls_metrics['precision']:.4f}, Recall={cls_metrics['recall']:.4f}, F1={cls_metrics['f1']:.4f}, Support={cls_metrics['support']}")

    # 5. Metadata verification
    print(f"\n[5/5] Storing and validating metadata at {HF_METRICS_PATH}...")
    if HF_METRICS_PATH.exists():
        with open(HF_METRICS_PATH, "r", encoding="utf-8") as f:
            meta = json.load(f)
        print(f"      • Base Model:    {meta.get('base_model')}")
        print(f"      • Model Version: {meta.get('model_version')}")
        print(f"      • Trained At:    {meta.get('trained_at')}")
        print(f"      • Verified OK.")

    print("\n" + "=" * 70)
    print("  TRACE//FIN DistilBERT Training Complete.")
    print("  The model is now immediately available in the UI and inference API.")
    print("=" * 70)


if __name__ == "__main__":
    main()
