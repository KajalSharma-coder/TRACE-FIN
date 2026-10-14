"""
TRACE//FIN — Model Training & Evaluation CLI (Phase 3)
Trains the reproducible TF-IDF + Logistic Regression baseline from back.dataset.csv.

Usage:
    python scripts/train_model.py
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import DATASET_PATH, METRICS_PATH, MODEL_PATH
from src.ml_model import train_model


def main() -> int:
    print("=" * 72)
    print(" TRACE//FIN — Suspicious Financial Advertisement ML Baseline Training")
    print(" Problem Statement: SKIT002 (AI & Cybercrime)")
    print("=" * 72)
    print(f"Dataset path : {DATASET_PATH}")
    print(f"Model target : {MODEL_PATH}")
    print(f"Metrics path : {METRICS_PATH}")
    print("-" * 72)

    try:
        metrics = train_model(
            dataset_path=DATASET_PATH,
            model_path=MODEL_PATH,
            metrics_path=METRICS_PATH,
        )

        print("\n✓ Training and evaluation completed successfully!")
        print(f"Model version       : {metrics['model_version']}")
        print(f"Algorithm           : {metrics['algorithm']}")
        print(f"Total dataset size  : {metrics['total_samples']} records")
        print(f"Training split      : {metrics['train_samples']} records")
        print(f"Test split (held-out): {metrics['test_samples']} records")
        print("-" * 72)

        print("\n[PERFORMANCE METRICS ON HELD-OUT TEST SPLIT]")
        print(f"Overall Accuracy    : {metrics['accuracy'] * 100:.2f}%")
        print(f"Macro Avg F1-Score  : {metrics['classification_report']['macro_avg_f1']:.4f}")

        cr = metrics["classification_report"]
        print("\nPer-Class Breakdown:")
        print(f"  • Safe       - Precision: {cr['Safe']['precision']:.4f} | Recall: {cr['Safe']['recall']:.4f} | F1: {cr['Safe']['f1_score']:.4f} (Support: {cr['Safe']['support']})")
        print(f"  • High Risk  - Precision: {cr['High Risk']['precision']:.4f} | Recall: {cr['High Risk']['recall']:.4f} | F1: {cr['High Risk']['f1_score']:.4f} (Support: {cr['High Risk']['support']})")

        cm = metrics["confusion_matrix"]
        print("\nConfusion Matrix:")
        print(f"  TN (Safe correctly identified)      : {cm['true_negatives_safe']}")
        print(f"  FP (Safe incorrectly flagged)       : {cm['false_positives']}")
        print(f"  FN (High Risk missed by ML)         : {cm['false_negatives']}")
        print(f"  TP (High Risk correctly identified) : {cm['true_positives_high_risk']}")

        print("\n[TOP HIGH-RISK VOCABULARY SIGNALS (POSITIVE COEFFICIENTS)]")
        for item in metrics["top_features"]["high_risk_signals"][:8]:
            print(f"  +{item['weight']:.4f}  {item['feature']}")

        print("\n[TOP SAFE / BENIGN VOCABULARY SIGNALS (NEGATIVE COEFFICIENTS)]")
        for item in metrics["top_features"]["safe_signals"][:8]:
            print(f"   {item['weight']:.4f}  {item['feature']}")

        print("\n[HONEST SCIENTIFIC LIMITATIONS & OBSERVATIONS]")
        for lim in metrics["limitations"]:
            print(f"  ℹ {lim}")

        print("=" * 72)
        print(f"Artifact successfully saved: {MODEL_PATH}")
        print("=" * 72)
        return 0

    except Exception as exc:
        print(f"\n❌ Error during model training: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
