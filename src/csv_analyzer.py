"""
TRACE//FIN — CSV Batch Analysis Module (Phase 4)
Upload, validate, batch-analyze advertisements from CSV, and export safe results.
Protects against formula injection in CSV exports.
"""

import io
import logging
import re
from typing import Any, Callable, Dict, List, Optional

import pandas as pd

from src.analysis_service import run_unified_analysis
from src.detector import analyze_ad
from src.ml_model import predict_ad_ml

logger = logging.getLogger("tracefin.csv")

# Limits
MAX_ROWS = 5000
MAX_SIZE_MB = 50
MIN_TEXT_LENGTH = 5

# Characters that can trigger formula injection in spreadsheets
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_cell(value: Any) -> str:
    """
    Sanitize a cell value to prevent CSV formula injection.
    Prepends a tab character to values starting with dangerous prefixes.
    """
    if not isinstance(value, str):
        return str(value) if value is not None else ""
    if value and value[0] in _FORMULA_PREFIXES:
        return "\t" + value
    return value


def validate_csv(
    uploaded_file,
    max_rows: int = MAX_ROWS,
    max_size_mb: float = MAX_SIZE_MB,
) -> Dict[str, Any]:
    """
    Validate an uploaded CSV file for encoding, size, row count.

    Returns:
        dict with keys: valid, error, df, row_count, columns
    """
    result = {
        "valid": False,
        "error": None,
        "df": None,
        "row_count": 0,
        "columns": [],
    }

    if uploaded_file is None:
        result["error"] = "No file uploaded."
        return result

    try:
        raw_bytes = uploaded_file.read()
        uploaded_file.seek(0)
    except Exception as exc:
        result["error"] = f"Cannot read file: {exc}"
        return result

    if len(raw_bytes) == 0:
        result["error"] = "Uploaded file is empty (0 bytes)."
        return result

    max_bytes = max_size_mb * 1024 * 1024
    if len(raw_bytes) > max_bytes:
        result["error"] = f"File too large ({len(raw_bytes)/1024/1024:.1f} MB). Maximum: {max_size_mb} MB."
        return result

    # Try multiple encodings
    df = None
    for encoding in ("utf-8", "utf-8-sig", "latin-1", "cp1252"):
        try:
            text = raw_bytes.decode(encoding)
            df = pd.read_csv(io.StringIO(text))
            break
        except (UnicodeDecodeError, pd.errors.ParserError):
            continue
        except Exception:
            continue

    if df is None:
        result["error"] = "Cannot parse CSV. Check file encoding and format."
        return result

    if len(df) == 0:
        result["error"] = "CSV file contains no data rows."
        return result

    if len(df) > max_rows:
        result["error"] = f"CSV has {len(df):,} rows. Maximum: {max_rows:,} rows."
        return result

    if len(df.columns) == 0:
        result["error"] = "CSV has no columns."
        return result

    result["valid"] = True
    result["df"] = df
    result["row_count"] = len(df)
    result["columns"] = list(df.columns)
    return result


def run_batch_analysis(
    df: pd.DataFrame,
    text_column: str,
    label_column: Optional[str] = None,
    progress_callback: Optional[Callable[[int, int], None]] = None,
    include_hf: bool = False,
) -> pd.DataFrame:
    """
    Run rule-based, ML baseline, and optional DistilBERT analysis on every row in the DataFrame
    using the shared analysis service contract and deterministic consensus verdict.

    Args:
        df: Input DataFrame.
        text_column: Column name containing advertisement text.
        label_column: Optional column name with ground-truth labels.
        progress_callback: Optional callback(current_row, total_rows).
        include_hf: Whether to include deep transformer (DistilBERT) inference for each row. Defaults to False for performance.

    Returns:
        DataFrame with standardized multi-engine and unified verdict results.
    """
    results = []
    total = len(df)

    for idx, row in df.iterrows():
        raw_text = str(row.get(text_column, "")).strip()

        # Validation for short or blank input
        if not raw_text or len(raw_text) < MIN_TEXT_LENGTH:
            entry = {
                "row_index": idx,
                "original_text": raw_text[:200] if raw_text else "",
                "final_verdict": None,
                "final_score": None,
                "risk_score": None,
                "risk_level": None,
                "rule_score": None,
                "rule_level": None,
                "matched_categories": "",
                "evidence_summary": "",
                "ml_prediction": None,
                "ml_confidence": None,
                "ml_model_version": None,
                "tfidf_status": "not_run",
                "tfidf_error": None,
                "hf_prediction": None,
                "hf_confidence": None,
                "distilbert_status": "not_run",
                "distilbert_error": None,
                "recommendation": "Text insufficient or empty",
                "investigation_status": None,
                "urls": "",
                "emails": "",
                "phone_numbers": "",
                "payment_identifiers": "",
                "review_required": None,
                "validation_status": "INVALID: Text too short or empty",
            }
            if label_column and label_column in row.index:
                entry["ground_truth"] = str(row[label_column])
            results.append(entry)
            if progress_callback:
                progress_callback(len(results), total)
            continue

        # Execute shared unified analysis contract across all engines
        analysis = run_unified_analysis(
            text=raw_text,
            source_type="CSV Batch",
            source_metadata={"row_index": idx},
            skip_hf=not include_hf,
        )

        # Standardized risk level for UI filters and backward compatibility
        v_level = analysis["final_verdict"]  # "HIGH RISK", "MEDIUM RISK", "LOW RISK"
        if v_level == "HIGH RISK":
            tier_label = "High"
        elif v_level == "MEDIUM RISK":
            tier_label = "Medium"
        elif v_level == "LOW RISK":
            tier_label = "Low"
        else:
            tier_label = "Unscored"

        entry = {
            "row_index": idx,
            "original_text": raw_text[:500],
            "final_verdict": analysis["final_verdict"],
            "final_score": analysis["final_score"],
            "risk_score": analysis["final_score"],
            "risk_level": tier_label,
            "rule_score": analysis["rule_score"],
            "rule_level": analysis["rule_level"],
            "matched_categories": "; ".join(analysis["matched_categories"]),
            "evidence_summary": "; ".join(analysis["evidence"][:5]),
            "ml_prediction": analysis["ml_prediction"],
            "ml_confidence": analysis["ml_confidence"],
            "ml_model_version": analysis["ml_model_version"],
            "tfidf_status": analysis.get("engine_status", {}).get("tfidf", "unknown"),
            "tfidf_error": analysis.get("engine_errors", {}).get("tfidf"),
            "hf_prediction": analysis["hf_prediction"],
            "hf_confidence": analysis["hf_confidence"],
            "distilbert_status": analysis.get("engine_status", {}).get("distilbert", "unknown"),
            "distilbert_error": analysis.get("engine_errors", {}).get("distilbert"),
            "recommendation": analysis["recommendation"],
            "investigation_status": analysis["investigation_status"],
            "urls": "; ".join(analysis["urls"]),
            "emails": "; ".join(analysis["emails"]),
            "phone_numbers": "; ".join(analysis["phone_numbers"]),
            "payment_identifiers": "; ".join(analysis["payment_identifiers"]),
            "review_required": "Yes" if analysis["review_required"] else "No",
            "validation_status": "OK",
        }
        if label_column and label_column in row.index:
            entry["ground_truth"] = str(row[label_column])

        results.append(entry)
        if progress_callback:
            progress_callback(len(results), total)

    return pd.DataFrame(results)


def export_safe_csv(df: pd.DataFrame) -> str:
    """
    Export a DataFrame to CSV string with formula injection protection.
    All string cells starting with dangerous characters are sanitized.
    """
    safe_df = df.copy()
    for col in safe_df.columns:
        if safe_df[col].dtype == object or pd.api.types.is_string_dtype(safe_df[col]):
            safe_df[col] = safe_df[col].astype(str).map(sanitize_cell)

    buf = io.StringIO()
    safe_df.to_csv(buf, index=False)
    return buf.getvalue()
