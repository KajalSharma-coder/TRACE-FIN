"""Offline browser rendering and TRACE//FIN analysis for untrusted URLs.

Network access is deliberately delegated to the existing SSRF-hardened fetcher.
Playwright receives escaped extracted text and never navigates remotely.
"""
from __future__ import annotations

import html
import re
from typing import Any

from src.analysis_service import run_unified_analysis
from src.url_fetcher import analyze_url


_SENSITIVE_TEXT_PATTERNS = [
    (re.compile(r"\b(account|acct|card|debit|credit|atm)(?:\s+(?:number|no))?\s*[:=#-]\s*(?:\d[ -]?){4,19}\b", re.I), r"\1: [REDACTED ACCOUNT/CARD NUMBER]"),
    (re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", re.I), "[REDACTED IFSC]"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "[REDACTED CARD/ACCOUNT NUMBER]"),
    (re.compile(r"\b(?:\+?\d[\d ()-]{8,}\d)\b"), "[REDACTED PHONE/NUMBER]"),
    (re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"), "[REDACTED EMAIL]"),
    (re.compile(r"\b[\w.-]{2,}@(?:upi|oksbi|okaxis|okhdfcbank|okicici|paytm)\b", re.I), "[REDACTED PAYMENT ID]"),
    (re.compile(r"\b(?:otp|one[ -]?time code|cvv|cvc|pin|password|passcode|token|session)[\s:=]+[^\s,;.!?]{2,}", re.I), "[REDACTED SECRET]"),
    (re.compile(r"([?&](?:token|access[_-]?token|refresh[_-]?token|auth|authorization|api[_-]?key|key|session(?:id)?|sid|password|passwd|otp|code|secret|credential)=)[^&#\s]+", re.I), r"\1[REDACTED]"),
]


def redact_sensitive_text(text: str) -> str:
    """Mask likely credentials and identifiers before model use or MCP output."""
    redacted = text or ""
    for pattern, replacement in _SENSITIVE_TEXT_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def _redact_url(url: str | None) -> str | None:
    if not url:
        return url
    url = re.sub(r"(?i)^((?:https?)://)[^/@?#]*@", r"\1[REDACTED]@", url, count=1)
    return re.sub(
        r"([?&](?:token|access[_-]?token|refresh[_-]?token|auth|authorization|api[_-]?key|key|"
        r"session(?:id)?|sid|password|passwd|otp|code|secret|credential)=)[^&#]+",
        r"\1[REDACTED]", url, flags=re.I,
    )


def analyze_browser_url(url: str, *, fetch_content: bool = True) -> dict[str, Any]:
    url_result = analyze_url(url, fetch_content=fetch_content)
    page_title = url_result.get("title", "")
    visible_text = redact_sensitive_text(url_result.get("extracted_text", ""))
    browser_available = False
    browser_error = None

    # Optional offline DOM extraction. No page-controlled scripts or network
    # requests are allowed to run in this browser context.
    if url_result.get("success") and url_result.get("analysis_mode") == "live_fetch":
        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                context = browser.new_context(java_script_enabled=False, service_workers="block")
                context.route("**/*", lambda route: route.abort())
                page = context.new_page()
                safe_html = (
                    "<!doctype html><html><head><title>"
                    + html.escape(redact_sensitive_text(page_title))
                    + "</title></head><body><pre>"
                    + html.escape(visible_text)
                    + "</pre></body></html>"
                )
                page.set_content(safe_html, wait_until="domcontentloaded", timeout=5000)
                page_title = page.title()
                visible_text = redact_sensitive_text(" ".join(page.locator("body").inner_text().split())[:200_000])
                context.close()
                browser.close()
                browser_available = True
        except ImportError:
            browser_error = "Playwright is not installed; used the safe HTML text extractor."
        except Exception as exc:
            browser_error = f"Offline browser parsing failed: {type(exc).__name__}: {exc}"

    url_model = dict(url_result.get("url_model") or {})
    if "url" in url_model:
        url_model["url"] = _redact_url(url_model["url"])
    if visible_text:
        ad_result = run_unified_analysis(
            visible_text,
            source_type="Website URL",
            source_metadata={"url": url, "final_url": url_result.get("final_url", url),
                             "url_model_results": [url_model]},
            skip_hf=True,
        )
        # The unified result contains extracted text and contact/payment
        # identifiers for the interactive app; MCP returns neither.
        ad_result.pop("analyzed_text", None)
        for sensitive_field in ("emails", "phone_numbers", "payment_identifiers", "urls", "source_metadata"):
            ad_result.pop(sensitive_field, None)
    else:
        ad_result = {
            "has_sufficient_evidence": False,
            "final_score": None,
            "final_verdict": "UNSCORED",
            "evidence": [],
            "extraction_error": url_result.get("error") or "No webpage text was extracted.",
            "engine_status": {},
        }

    return {
        "url": _redact_url(url),
        "final_url": _redact_url(url_result.get("final_url", url)),
        "redirects": url_result.get("metadata", {}).get("redirects", 0),
        "redirect_history": [
            {**hop, "from": _redact_url(hop.get("from")), "to": _redact_url(hop.get("to"))}
            for hop in url_result.get("redirect_history", [])
        ],
        "title": redact_sensitive_text(page_title),
        "visible_text": visible_text,
        "fetch_success": bool(url_result.get("success") and url_result.get("analysis_mode") == "live_fetch"),
        "analysis_mode": url_result.get("analysis_mode"),
        "fetch_error": redact_sensitive_text(url_result.get("error") or "") or None,
        "failure_category": url_result.get("failure_category"),
        "url_model": url_model,
        "advertisement_analysis": ad_result,
        "browser_rendered": browser_available,
        "browser_error": browser_error,
        "url_indicators": url_result.get("indicators", []),
    }
