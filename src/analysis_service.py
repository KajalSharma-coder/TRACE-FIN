"""
TRACE//FIN — Shared Multi-Format Analysis Service
Canonical analysis contract across all ingestion pipelines:
- Direct Text
- Website URL
- Image / Screenshot OCR
- PDF Document
- Word Document (DOCX)
- CSV Batch Analysis

Preserves format-specific extraction logic while guaranteeing that all extracted
advertisement content is processed through the exact same multi-engine triage pipeline:
Rule Heuristics -> TF-IDF ML Baseline -> DistilBERT Classifier -> compute_unified_verdict -> SQLite DB.
"""

from typing import Any, Dict, Optional
import logging

from src.database import generate_record_id, insert_record
from src.detector import analyze_ad, compute_unified_verdict
from src.ml_model import predict_ad_ml
from src.hf_model import predict_ad_hf

logger = logging.getLogger("tracefin.analysis_service")

# Standard Extraction Status Constants
STATUS_SUCCESS = "SUCCESS"
STATUS_EMPTY_INPUT = "EMPTY_INPUT"
STATUS_INSUFFICIENT_CONTENT = "INSUFFICIENT_CONTENT"
STATUS_EXTRACTION_FAILED = "EXTRACTION_FAILED"
STATUS_SYNTAX_ONLY = "SYNTAX_ONLY"


def _normalize_urls_list(raw_urls: Any) -> list[str]:
    """Ensure URLs are returned as a deduplicated list of clean string URLs, never split characters."""
    if not raw_urls:
        return []
    if isinstance(raw_urls, str):
        s = raw_urls.strip()
        if not s or s == "[]":
            return []
        if s.startswith("[") and s.endswith("]"):
            try:
                import json
                parsed = json.loads(s)
                if isinstance(parsed, list):
                    return [str(u).strip() for u in parsed if str(u).strip()]
            except Exception:
                pass
        return [s]
    if isinstance(raw_urls, (list, tuple, set)):
        # Guard against list of single characters from iterating a string
        if all(isinstance(c, str) and len(c) == 1 for c in raw_urls) and len(raw_urls) > 3:
            reconstructed = "".join(raw_urls).strip()
            return [reconstructed] if reconstructed else []
        result = []
        for item in raw_urls:
            if isinstance(item, str) and item.strip():
                result.append(item.strip())
        return list(dict.fromkeys(result))
    return []


def _classify_urls(raw_urls: Any) -> list[Dict[str, Any]]:
    """Classify extracted URLs as an explicitly supplementary phishing signal."""
    try:
        from src.url_model import classify_url
        return [classify_url(url) for url in _normalize_urls_list(raw_urls)[:20]]
    except Exception as exc:
        logger.warning("URL model unavailable: %s", exc)
        return [{"available": False, "prediction": None, "phishing_probability": None,
                 "error": str(exc), "model": "pirocheto/phishing-url-detection (ONNX)"}]


def _url_model_evidence(results: list[Dict[str, Any]]) -> list[str]:
    lines = []
    for result in results:
        if result.get("available"):
            likelihood = result.get("phishing_probability")
            pct = f"{likelihood:.1%}" if isinstance(likelihood, (int, float)) else "unknown likelihood"
            lines.append(f"[Supplementary URL model] {result.get('prediction')} ({pct} phishing likelihood); does not affect financial-ad risk score.")
        elif result.get("error"):
            lines.append(f"[Supplementary URL model unavailable] {result['error']}")
    return lines


def _url_results_from_metadata(source_meta: Dict[str, Any], fallback_text: str = "") -> list[Dict[str, Any]]:
    results = source_meta.get("url_model_results") or source_meta.get("url_model")
    if isinstance(results, dict):
        return [results]
    if results:
        return list(results)
    url = source_meta.get("final_url") or source_meta.get("url")
    if not url and fallback_text.startswith(("http://", "https://")) and " " not in fallback_text:
        url = fallback_text
    return _classify_urls(url) if url else []


def run_unified_analysis(
    text: Optional[str],
    source_type: str = "Direct Text",
    source_metadata: Optional[Dict[str, Any]] = None,
    extraction_status: str = STATUS_SUCCESS,
    extraction_error: Optional[str] = None,
    skip_hf: bool = False,
) -> Dict[str, Any]:
    """
    Execute standardized multi-engine analysis according to the unified contract.

    Args:
        text: Extracted or submitted advertisement text.
        source_type: Ingestion method name ('Direct Text', 'Website URL', 'Image OCR', 'PDF Document', 'Word Document', 'CSV Batch').
        source_metadata: Format-specific metadata (file size, dimensions, URL status, etc.).
        extraction_status: Extraction result status code.
        extraction_error: Error message if extraction failed or was incomplete.
        skip_hf: If True, skips DistilBERT inference (e.g. for high-throughput batch). Defaults to False.

    Returns:
        Standardized dictionary containing all engine metrics, final verdict,
        investigator recommendation, and case status.
    """
    clean_text = (text or "").strip()
    source_meta = dict(source_metadata or {})

    # ── 1. Check for bare URL directly input in Direct Text ────────────────
    if source_type == "Direct Text" and (clean_text.startswith("http://") or clean_text.startswith("https://")) and " " not in clean_text:
        url_results = _classify_urls(clean_text)
        return {
            "source_type": source_type,
            "extraction_status": STATUS_SYNTAX_ONLY,
            "extraction_error": "Direct text input contains only a bare URL without extracted webpage content.",
            "analyzed_text": clean_text,
            "has_sufficient_evidence": False,
            "final_verdict": "INSUFFICIENT EVIDENCE",
            "final_score": None,
            "risk_score": 0,
            "risk_level": "Unscored",
            "rule_score": 0,
            "rule_level": "Unscored",
            "matched_rules": [],
            "matched_categories": [],
            "evidence": ["Direct text input is a bare URL; live webpage content was not retrieved."] + _url_model_evidence(url_results),
            "url_model_results": url_results,
            "urls": [clean_text],
            "emails": [],
            "phone_numbers": [],
            "payment_identifiers": [],
            "ml_prediction": None,
            "ml_confidence": None,
            "ml_decision_score": None,
            "ml_model_version": None,
            "ml_top_signals": [],
            "hf_prediction": None,
            "hf_confidence": None,
            "hf_model_version": None,
            "explanation": "A bare URL was submitted as text without webpage content. To inspect website content, use the 'Website URL' tab with live content fetch enabled.",
            "recommendation": "Manual Inspection Required: Switch to the Website URL intake tab to safely fetch and inspect live webpage content.",
            "investigation_status": "Reviewing",
            "review_required": True,
            "source_metadata": source_meta,
        }

    # ── 2. Check for failed, empty, syntax-only, or insufficient content ────
    if extraction_status == STATUS_SYNTAX_ONLY:
        meta_url = source_meta.get("final_url") or source_meta.get("url") or (clean_text if clean_text.startswith("http") else None)
        url_results = _url_results_from_metadata(source_meta, clean_text)
        return {
            "source_type": source_type,
            "extraction_status": STATUS_SYNTAX_ONLY,
            "extraction_error": extraction_error or "Only domain syntax analyzed; page content was not fetched.",
            "analyzed_text": clean_text,
            "has_sufficient_evidence": False,
            "final_verdict": "INSUFFICIENT EVIDENCE",
            "final_score": None,
            "risk_score": 0,
            "risk_level": "Unscored",
            "rule_score": 0,
            "rule_level": "Unscored",
            "matched_rules": [],
            "matched_categories": [],
            "evidence": ["Domain syntax only; live page content was not fetched or accessible."] + _url_model_evidence(url_results),
            "url_model_results": url_results,
            "urls": _normalize_urls_list(meta_url),
            "emails": [],
            "phone_numbers": [],
            "payment_identifiers": [],
            "ml_prediction": None,
            "ml_confidence": None,
            "ml_decision_score": None,
            "ml_model_version": None,
            "ml_top_signals": [],
            "hf_prediction": None,
            "hf_confidence": None,
            "hf_model_version": None,
            "explanation": "Domain syntax alone is insufficient to verify advertisement risk. Live webpage content must be retrieved for automated threat scoring.",
            "recommendation": "Manual Inspection Required: Enable live content fetch or manually transcribe page content.",
            "investigation_status": "Reviewing",
            "review_required": True,
            "source_metadata": source_meta,
        }

    if extraction_status == STATUS_EXTRACTION_FAILED or extraction_error:
        is_url_source = "url" in str(source_type).lower() or "website" in str(source_type).lower()
        fetch_failure_category = source_meta.get("fetch_failure_category")
        is_network_failure = fetch_failure_category in {
            "dns_resolution_failed", "connection_failed", "connection_timeout", "tls_error"
        }
        is_ssrf_block = fetch_failure_category == "ssrf_blocked"
        err_msg = extraction_error or ("Webpage content could not be retrieved." if is_url_source else "Content extraction failed.")
        meta_url = source_meta.get("final_url") or source_meta.get("url") or (clean_text if clean_text.startswith("http") else None)
        url_results = _url_results_from_metadata(source_meta, clean_text)
        if is_url_source and is_network_failure:
            explanation = (
                f"The page could not be fetched because of a DNS or network problem: {err_msg}. "
                "This failure does not indicate that the URL is suspicious. Page content was unavailable, so its risk remains unscored."
            )
            recommendation = "Check the app's internet/DNS connectivity and the URL spelling, then retry. If it remains unreachable, inspect the page manually in a sandboxed browser."
        elif is_url_source and is_ssrf_block:
            explanation = f"The URL was blocked by the SSRF safety check: {err_msg}. No page content was fetched and no risk score was produced."
            recommendation = "Do not bypass the SSRF protection. Review the target and its resolved address through an approved, isolated investigation environment."
        else:
            explanation = (
                f"Webpage content could not be retrieved: {err_msg}. Automated scoring cannot be performed without accessible webpage content."
                if is_url_source else
                f"Document/media extraction failed: {err_msg}. Automated scoring cannot be performed on unextracted files."
            )
            recommendation = (
                "Manual Inspection Required: Verify network connectivity, confirm the URL is reachable, or manually inspect the target site in a sandboxed browser."
                if is_url_source else
                "Manual Inspection Required: Verify file integrity, check format compatibility, or transcribe text manually."
            )
        return {
            "source_type": source_type,
            "extraction_status": STATUS_EXTRACTION_FAILED,
            "extraction_error": err_msg,
            "analyzed_text": clean_text,
            "has_sufficient_evidence": False,
            "final_verdict": "INSUFFICIENT EVIDENCE",
            "final_score": None,
            "risk_score": 0,
            "risk_level": "Unscored",
            "rule_score": 0,
            "rule_level": "Unscored",
            "matched_rules": [],
            "matched_categories": [],
            "evidence": [f"Extraction error: {err_msg}"] + _url_model_evidence(url_results),
            "url_model_results": url_results,
            "urls": _normalize_urls_list(meta_url),
            "emails": [],
            "phone_numbers": [],
            "payment_identifiers": [],
            "ml_prediction": None,
            "ml_confidence": None,
            "ml_decision_score": None,
            "ml_model_version": None,
            "ml_top_signals": [],
            "hf_prediction": None,
            "hf_confidence": None,
            "hf_model_version": None,
            "explanation": explanation,
            "recommendation": recommendation,
            "investigation_status": "Reviewing",
            "review_required": True,
            "source_metadata": source_meta,
        }

    if not clean_text:
        url_results = _url_results_from_metadata(source_meta)
        return {
            "source_type": source_type,
            "extraction_status": STATUS_EMPTY_INPUT,
            "extraction_error": "Input text is blank.",
            "analyzed_text": "",
            "has_sufficient_evidence": False,
            "final_verdict": "INSUFFICIENT EVIDENCE",
            "final_score": None,
            "risk_score": 0,
            "risk_level": "Unscored",
            "rule_score": 0,
            "rule_level": "Unscored",
            "matched_rules": [],
            "matched_categories": [],
            "evidence": ["No advertisement text provided."] + _url_model_evidence(url_results),
            "url_model_results": url_results,
            "urls": [],
            "emails": [],
            "phone_numbers": [],
            "payment_identifiers": [],
            "ml_prediction": None,
            "ml_confidence": None,
            "ml_decision_score": None,
            "ml_model_version": None,
            "ml_top_signals": [],
            "hf_prediction": None,
            "hf_confidence": None,
            "hf_model_version": None,
            "explanation": "No advertisement text was provided or extracted. Numerical risk score is unavailable.",
            "recommendation": "Manual Inspection Required: Ingest or transcribe valid advertisement content.",
            "investigation_status": "Reviewing",
            "review_required": True,
            "source_metadata": source_meta,
        }

    if len(clean_text) < 5:
        url_results = _url_results_from_metadata(source_meta, clean_text)
        return {
            "source_type": source_type,
            "extraction_status": STATUS_INSUFFICIENT_CONTENT,
            "extraction_error": f"Content too short ({len(clean_text)} chars; minimum is 5).",
            "analyzed_text": clean_text,
            "has_sufficient_evidence": False,
            "final_verdict": "INSUFFICIENT EVIDENCE",
            "final_score": None,
            "risk_score": 0,
            "risk_level": "Unscored",
            "rule_score": 0,
            "rule_level": "Unscored",
            "matched_rules": [],
            "matched_categories": [],
            "evidence": ["Provided text is too short for reliable threat pattern analysis."] + _url_model_evidence(url_results),
            "url_model_results": url_results,
            "urls": [],
            "emails": [],
            "phone_numbers": [],
            "payment_identifiers": [],
            "ml_prediction": None,
            "ml_confidence": None,
            "ml_decision_score": None,
            "ml_model_version": None,
            "ml_top_signals": [],
            "hf_prediction": None,
            "hf_confidence": None,
            "hf_model_version": None,
            "explanation": f"Text length ({len(clean_text)} chars) is below the minimum operational threshold for threat intelligence.",
            "recommendation": "Manual Review Required: Verify full advertisement text.",
            "investigation_status": "Reviewing",
            "review_required": True,
            "source_metadata": source_meta,
        }

    # ── 2. Content is valid: Execute Shared Core Pipeline ──────────────────
    rule_result = analyze_ad(clean_text)

    try:
        ml_result = predict_ad_ml(clean_text)
    except Exception as exc:
        logger.error("TF-IDF ML inference failed: %s", exc)
        ml_result = {"available": False, "risk_label": None, "confidence": None, "model_version": None, "error": str(exc)}

    if skip_hf:
        hf_result = {"available": False, "risk_label": None, "confidence": None, "model_version": None}
    else:
        try:
            hf_result = predict_ad_hf(clean_text)
        except Exception as exc:
            logger.error("DistilBERT inference failed: %s", exc)
            hf_result = {"available": False, "risk_label": None, "confidence": None, "model_version": None, "error": str(exc)}

    # Synthesize unified verdict using the exact deterministic combination strategy
    verdict_data = compute_unified_verdict(rule_result, ml_result, hf_result)

    final_score = verdict_data["final_score"]
    final_verdict = verdict_data["final_verdict"]

    engine_status = {
        "rules": "available",
        "tfidf": "available" if ml_result.get("available") else "unavailable",
        "distilbert": "skipped" if skip_hf else ("available" if hf_result.get("available") else "unavailable"),
    }
    engine_errors = {
        "tfidf": ml_result.get("error") if not ml_result.get("available") else None,
        "distilbert": (
            "Inference skipped for batch performance." if skip_hf else
            (hf_result.get("error") if not hf_result.get("available") else None)
        ),
    }
    model_issues = [
        f"{name}: {error}" for name, error in engine_errors.items() if error
    ]
    evidence = list(rule_result.get("evidence", []))
    evidence.extend(f"[Model Availability] {issue}" for issue in model_issues)

    # Merge any URLs from rule_result with source_metadata URLs
    merged_urls = list(rule_result.get("urls", []))
    meta_url = source_meta.get("final_url") or source_meta.get("url")
    if meta_url:
        merged_urls.extend(_normalize_urls_list(meta_url))
    clean_urls = _normalize_urls_list(merged_urls)
    url_results = _url_results_from_metadata(source_meta) or _classify_urls(clean_urls)
    evidence.extend(_url_model_evidence(url_results))
    source_meta["url_model_results"] = url_results
    if clean_urls or url_results:
        engine_status["url_model"] = "available" if any(item.get("available") for item in url_results) else "unavailable"
        engine_errors["url_model"] = next((item.get("error") for item in url_results if item.get("error")), None)

    return {
        "source_type": source_type,
        "extraction_status": STATUS_SUCCESS,
        "extraction_error": None,
        "analyzed_text": clean_text,
        "has_sufficient_evidence": final_score is not None,
        "final_verdict": final_verdict,
        "final_score": final_score,
        "risk_score": final_score,
        "risk_level": final_verdict,
        "rule_score": rule_result["risk_score"],
        "rule_level": rule_result["risk_level"],
        "matched_rules": rule_result.get("matched_rules", []),
        "matched_categories": rule_result.get("matched_categories", []),
        "evidence": evidence,
        "urls": clean_urls,
        "emails": rule_result.get("emails", []),
        "phone_numbers": rule_result.get("phone_numbers", []),
        "payment_identifiers": rule_result.get("payment_identifiers", []),
        "ml_prediction": ml_result.get("risk_label"),
        "ml_confidence": ml_result.get("confidence"),
        "ml_decision_score": ml_result.get("high_risk_score"),
        "ml_model_version": ml_result.get("model_version"),
        "ml_top_signals": ml_result.get("top_signals", []),
        "hf_prediction": hf_result.get("risk_label"),
        "hf_confidence": hf_result.get("confidence"),
        "hf_class_probabilities": hf_result.get("class_probabilities"),
        "hf_decision_score": hf_result.get("high_risk_score"),
        "hf_model_version": hf_result.get("model_version"),
        "url_model_results": url_results,
        "engine_status": engine_status,
        "engine_errors": engine_errors,
        "explanation": verdict_data["explanation"],
        "recommendation": verdict_data["recommendation"],
        "investigation_status": verdict_data["investigation_status"],
        "review_required": verdict_data["review_required"],
        "badge_color": verdict_data.get("badge_color", "#38bdf8"),
        "consensus_status": verdict_data.get("consensus_status", "Evaluated"),
        "source_metadata": source_meta,
    }


def persist_analysis_record(
    analysis_result: Dict[str, Any],
    custom_record_id: Optional[str] = None,
) -> str:
    """
    Format and persist the standardized analysis result into the SQLite database.

    Args:
        analysis_result: Output dictionary from run_unified_analysis().
        custom_record_id: Optional predetermined ID. If None, generates a UUID record ID.

    Returns:
        The inserted record_id string.
    """
    record_id = custom_record_id or generate_record_id()
    src_tag = str(analysis_result.get("source_type", "direct_text")).lower().replace(" ", "_")
    analysis_mode = f"{src_tag}_unified"

    score_val = analysis_result.get("final_score")
    stored_score = int(score_val) if score_val is not None else None

    record = {
        "record_id": record_id,
        "ad_text": analysis_result.get("analyzed_text", ""),
        "analysis_mode": analysis_mode,
        "risk_score": stored_score,
        "risk_level": analysis_result.get("final_verdict", "Unscored"),
        "matched_categories": analysis_result.get("matched_categories", []),
        "evidence": analysis_result.get("evidence", []),
        "urls": _normalize_urls_list(analysis_result.get("urls", [])),
        "emails": analysis_result.get("emails", []),
        "phone_numbers": analysis_result.get("phone_numbers", []),
        "payment_identifiers": analysis_result.get("payment_identifiers", []),
        "review_required": analysis_result.get("review_required", True),
        "review_recommendation": analysis_result.get("recommendation", "Review required"),
        "investigation_status": analysis_result.get("investigation_status", "Open"),
        "is_synthetic": False,
        "ml_prediction": analysis_result.get("ml_prediction"),
        "ml_confidence": analysis_result.get("ml_confidence"),
        "ml_high_risk_score": analysis_result.get("ml_decision_score"),
        "ml_model_version": analysis_result.get("ml_model_version"),
        "hf_prediction": analysis_result.get("hf_prediction"),
        "hf_confidence": analysis_result.get("hf_confidence"),
        "hf_model_version": analysis_result.get("hf_model_version"),
    }

    insert_record(record)
    return record_id
