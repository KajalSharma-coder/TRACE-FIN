#!/usr/bin/env python3
"""Read-only quality audit for TRACE//FIN curated training candidates.

This module deliberately does not merge candidates into the production dataset
and does not write an audit file. It can be imported by tests or run as a CLI.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from collections import defaultdict
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = PROJECT_ROOT / "data" / "curated_candidates.csv"

REQUIRED_COLUMNS = (
    "Candidate_ID",
    "Advertisement_Text",
    "Risk_Label",
    "Content_Subtype",
    "Source_Provenance",
    "Campaign_or_Template_Group",
    "Collection_Date",
    "Evidence",
    "Review_Status",
    "Is_Synthetic",
)
OPTIONAL_COLUMNS = ("Assigned_Split",)
VALID_LABELS = {"Safe", "High Risk"}
VALID_REVIEW_STATUSES = {"Reviewed", "Needs Review", "Rejected"}
TRUE_BOOLEAN_VALUES = {"true", "1", "yes", "y", "synthetic"}
FALSE_BOOLEAN_VALUES = {"false", "0", "no", "n", "real", ""}
TARGET_TEMPLATES_PER_CLASS = 60
TARGET_TEST_TEMPLATES_PER_CLASS = 12
MIN_REVIEWED_VARIANTS = 5


def _text(value: Any) -> str:
    if value is None or pd.isna(value):
        return ""
    return str(value).strip()


def _parse_boolean(value: Any) -> bool | None:
    """Parse an intake boolean; blank values are unknown, not an error."""
    normalized = _text(value).casefold()
    if normalized in TRUE_BOOLEAN_VALUES:
        return True
    if normalized in FALSE_BOOLEAN_VALUES:
        return False
    return None


def _is_true(value: Any) -> bool:
    """Return True only for an explicitly true value.

    Blank, missing, whitespace-only, and invalid values are safely false here;
    audit_dataset separately reports invalid nonblank values.
    """
    return _parse_boolean(value) is True


def _count_truthy(values: Any) -> int:
    """Count truthy values without relying on pandas' empty-object sum behavior."""
    return sum(bool(value) for value in values)


def normalize_text(value: Any) -> str:
    """Normalize variable formatting for duplicate and family detection."""
    text = unicodedata.normalize("NFKC", _text(value)).casefold()
    text = re.sub(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", " <ifsc> ", text, flags=re.I)
    text = re.sub(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}", " <email> ", text, flags=re.I)
    text = re.sub(r"(?:https?://|www\.)\S+", " <url> ", text, flags=re.I)
    text = re.sub(r"\b\d[\d -]{6,}\d\b", " <number> ", text)
    text = re.sub(r"[^\w<>]+", " ", text)
    return " ".join(text.split())


def detect_pii(value: Any) -> list[str]:
    """Return conservative PII indicators without returning the matched value."""
    text = _text(value)
    findings: set[str] = set()
    if re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text):
        findings.add("email")
    if re.search(r"(?<!\w)(?:\+?\d[\d ().-]{7,}\d)(?!\w)", text):
        findings.add("phone_or_long_number")
    if re.search(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", text, flags=re.I):
        findings.add("ifsc")
    if re.search(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)", text):
        findings.add("card_or_account_number")
    if re.search(r"\b[\w.-]{2,}@(upi|ybl|okaxis|okhdfcbank|okicici|oksbi)\b", text, flags=re.I):
        findings.add("upi_identifier")
    # Names cannot be reliably inferred from free text. Flag likely names only
    # when introduced by an identity/contact marker, for human confirmation.
    if re.search(
        r"\b(?:account holder|send to|contact|attn|mr\.?|mrs\.?|ms\.?)\s+"
        r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}\b",
        text,
    ):
        findings.add("possible_person_name")
    return sorted(findings)


def _group_value(row: pd.Series, normalized: str) -> str:
    explicit = _text(row.get("Campaign_or_Template_Group"))
    return f"declared:{explicit.casefold()}" if explicit else f"normalized:{normalized}"


def _near_duplicate_pairs(values: list[str], threshold: float = 0.92) -> list[tuple[int, int, float]]:
    pairs: list[tuple[int, int, float]] = []
    for left in range(len(values)):
        for right in range(left + 1, len(values)):
            if not values[left] or not values[right]:
                continue
            ratio = SequenceMatcher(None, values[left], values[right]).ratio()
            if ratio >= threshold and values[left] != values[right]:
                pairs.append((left, right, round(ratio, 4)))
    return pairs


def audit_dataset(path: Path = DEFAULT_INPUT, near_duplicate_threshold: float = 0.92) -> dict[str, Any]:
    """Audit a candidate CSV without modifying it or any project artifact."""
    if not path.exists():
        return {"path": str(path), "errors": [f"Input file does not exist: {path}"], "ready": False}
    try:
        df = pd.read_csv(path, dtype=str, keep_default_na=False)
    except Exception as exc:
        return {"path": str(path), "errors": [f"Could not read CSV: {exc}"], "ready": False}

    errors: list[str] = []
    warnings: list[str] = []
    missing = [column for column in REQUIRED_COLUMNS if column not in df.columns]
    if missing:
        errors.append(f"Missing required columns: {', '.join(missing)}")
    if errors:
        return {"path": str(path), "rows": len(df), "errors": errors, "warnings": warnings, "ready": False}

    blank_fields = {
        column: _count_truthy(df[column].map(_text).eq(""))
        for column in REQUIRED_COLUMNS
        if _count_truthy(df[column].map(_text).eq(""))
    }
    if blank_fields:
        errors.append(f"Required fields contain blanks: {blank_fields}")

    invalid_labels = sorted(set(df["Risk_Label"].map(_text)) - VALID_LABELS)
    if invalid_labels:
        errors.append(f"Invalid labels: {invalid_labels}")
    invalid_statuses = sorted(set(df["Review_Status"].map(_text)) - VALID_REVIEW_STATUSES)
    if invalid_statuses:
        errors.append(f"Invalid review statuses: {invalid_statuses}")

    normalized = df["Advertisement_Text"].map(normalize_text)
    pii = df["Advertisement_Text"].map(detect_pii)
    df_work = df.copy()
    df_work["_normalized"] = normalized
    df_work["_pii"] = pii
    df_work["_group"] = [
        _group_value(row, norm) for (_, row), norm in zip(df.iterrows(), normalized)
    ]

    exact_duplicate_rows = _count_truthy(df["Advertisement_Text"].duplicated(keep=False))
    normalized_duplicate_rows = _count_truthy(normalized.duplicated(keep=False))
    if exact_duplicate_rows:
        warnings.append(f"Exact duplicate rows detected: {exact_duplicate_rows}")
    if normalized_duplicate_rows:
        warnings.append(f"Normalized duplicate rows detected: {normalized_duplicate_rows}")

    near_pairs = _near_duplicate_pairs(normalized.tolist(), near_duplicate_threshold)
    if near_pairs:
        warnings.append(f"Near-duplicate pairs detected: {len(near_pairs)}")

    conflict_groups: dict[str, list[str]] = {}
    for group, subset in df_work.groupby("_group"):
        labels = sorted(set(subset["Risk_Label"].map(_text)))
        if len(labels) > 1:
            conflict_groups[group] = labels
    if conflict_groups:
        warnings.append(f"Conflicting labels require human adjudication: {len(conflict_groups)} groups")

    synthetic_values = df["Is_Synthetic"].map(_parse_boolean)
    synthetic_flags = pd.Series(
        [parsed is True for parsed in synthetic_values], index=df.index, dtype=bool
    )
    invalid_synthetic_values = sorted({
        _text(value)
        for value, parsed in zip(df["Is_Synthetic"], synthetic_values)
        if _text(value) and parsed is None
    })
    if invalid_synthetic_values:
        warnings.append(
            "Invalid Is_Synthetic values treated as unknown and excluded from "
            f"synthetic counts: {invalid_synthetic_values}"
        )
    synthetic_rows = _count_truthy(synthetic_flags)
    if synthetic_rows:
        warnings.append(f"Synthetic rows are excluded from training readiness: {synthetic_rows}")
    unverified_rows = _count_truthy(
        df["Source_Provenance"].map(_text).str.casefold().str.startswith(
            ("unknown", "unverified", "self-authored")
        )
    )
    if unverified_rows:
        warnings.append(f"Unverified provenance rows are excluded from readiness: {unverified_rows}")
    pii_rows = _count_truthy(pii)
    if pii_rows:
        warnings.append(f"Rows with possible PII require redaction/review: {pii_rows}")

    reviewed = df["Review_Status"].map(_text).eq("Reviewed")
    synthetic = synthetic_flags
    provenance = ~df["Source_Provenance"].map(_text).str.casefold().str.startswith(("unknown", "unverified", "self-authored"))
    pii_flags = pd.Series([bool(findings) for findings in pii], index=df.index, dtype=bool)
    conflict_group_names = set(conflict_groups)
    eligible = (
        reviewed.astype(bool)
        & ~synthetic
        & provenance.astype(bool)
        & ~pii_flags
        & ~df_work["_group"].isin(conflict_group_names).astype(bool)
    )
    eligible &= df["Risk_Label"].map(_text).isin(VALID_LABELS)
    eligible_templates = df_work.loc[eligible].groupby(["Risk_Label", "_group"], dropna=False).size()
    template_counts = {label: int(eligible_templates.loc[label].size) if label in eligible_templates.index.get_level_values(0) else 0 for label in VALID_LABELS}
    variant_counts = {
        label: int(sum(count >= MIN_REVIEWED_VARIANTS for (group_label, _), count in eligible_templates.items() if group_label == label))
        for label in VALID_LABELS
    }

    split_report: dict[str, Any] = {"assessed": False, "leakage": {}, "ready": False}
    if "Assigned_Split" in df.columns and df["Assigned_Split"].map(_text).ne("").any():
        split_values = df["Assigned_Split"].map(_text).str.casefold()
        allowed_splits = {"train", "validation", "val", "test"}
        bad_splits = sorted(set(split_values[split_values.ne("")]) - allowed_splits)
        if bad_splits:
            errors.append(f"Invalid Assigned_Split values: {bad_splits}")
        split_report["assessed"] = True
        leakage: dict[str, list[str]] = {}
        for column in ("_group", "Source_Provenance"):
            overlaps: set[str] = set()
            for _, subset in df_work.loc[split_values.ne("")].groupby(column):
                if subset["Assigned_Split"].map(_text).str.casefold().nunique() > 1:
                    overlaps.add(str(_))
            leakage[column] = sorted(overlaps)
        split_report["leakage"] = leakage
        split_report["ready"] = not bad_splits and not any(leakage.values())
    else:
        warnings.append("No Assigned_Split values supplied; leakage can only be checked after a frozen grouped split is assigned.")

    split_report["eligible_class_template_counts"] = template_counts
    split_report["target_templates_per_class"] = TARGET_TEMPLATES_PER_CLASS
    split_report["target_test_templates_per_class"] = TARGET_TEST_TEMPLATES_PER_CLASS
    split_report["grouped_readiness"] = all(
        template_counts.get(label, 0) >= TARGET_TEMPLATES_PER_CLASS for label in VALID_LABELS
    )
    if not split_report["grouped_readiness"]:
        warnings.append("Provisional grouped training target is not met: need at least 60 eligible templates per class.")

    result = {
        "path": str(path),
        "rows": len(df),
        "errors": errors,
        "warnings": warnings,
        "ready": not errors and bool(split_report["grouped_readiness"]) and split_report["ready"] if split_report["assessed"] else not errors and bool(split_report["grouped_readiness"]),
        "class_counts": {str(k): int(v) for k, v in df["Risk_Label"].map(_text).value_counts().items()},
        "eligible_rows": _count_truthy(eligible),
        "eligible_template_counts": template_counts,
        "templates_with_at_least_five_reviewed_variants": variant_counts,
        "exact_duplicate_rows": exact_duplicate_rows,
        "normalized_duplicate_rows": normalized_duplicate_rows,
        "near_duplicate_pairs": near_pairs,
        "conflicting_groups": conflict_groups,
        "pii_rows": pii_rows,
        "pii_categories": sorted({category for findings in pii for category in findings}),
        "synthetic_rows": synthetic_rows,
        "invalid_synthetic_values": invalid_synthetic_values,
        "unverified_provenance_rows": unverified_rows,
        "split": split_report,
    }
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only audit of TRACE//FIN curated candidates")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--near-duplicate-threshold", type=float, default=0.92)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    result = audit_dataset(args.input, args.near_duplicate_threshold)
    if args.as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Input: {result['path']}")
        print(f"Rows: {result.get('rows', 0)} | Eligible: {result.get('eligible_rows', 0)}")
        print(f"Eligible templates: {result.get('eligible_template_counts', {})}")
        print(f"Training readiness: {'READY' if result.get('ready') else 'NOT READY'}")
        for heading in ("errors", "warnings"):
            for message in result.get(heading, []):
                print(f"{heading[:-1].upper()}: {message}")
    return 0 if result.get("ready") else 1


if __name__ == "__main__":
    sys.exit(main())
