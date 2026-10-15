from unittest.mock import patch

from src.browser_analysis import analyze_browser_url, redact_sensitive_text, _redact_url


def test_sensitive_identifiers_are_redacted_before_analysis_output():
    redacted = redact_sensitive_text("Account: 123456789012 and OTP: 345678")
    assert "123456789012" not in redacted
    assert "345678" not in redacted
    assert "password" not in _redact_url("https://user:password@example.test/?api_key=secret")
    assert "secret" not in _redact_url("https://user:password@example.test/?api_key=secret")
    assert redact_sensitive_text("Suspicious Financial Advertisement") == "Suspicious Financial Advertisement"
    assert redact_sensitive_text("Bank code HDFC0123456") == "Bank code [REDACTED IFSC]"


def test_browser_analysis_suspicious_financial_ad_uses_existing_pipeline():
    fetched = {
        "valid": True, "success": True, "url": "https://example.test/ad",
        "analysis_mode": "live_fetch",
        "final_url": "https://example.test/ad", "title": "Verify your bank account",
        "extracted_text": "Your bank account will be blocked. Verify now and send your OTP.",
        "html_content": "<title>Verify your bank account</title><p>Your bank account will be blocked. Verify now and send your OTP.</p>",
        "redirect_history": [], "metadata": {"redirects": 0}, "indicators": [],
        "url_model": {"available": False, "prediction": None, "error": "test unavailable"},
    }
    with patch("src.browser_analysis.analyze_url", return_value=fetched):
        result = analyze_browser_url("https://example.test/ad")
    ad = result["advertisement_analysis"]
    assert result["title"]
    assert ad["final_score"] is not None
    assert ad["evidence"]
    assert result["url_model"]["available"] is False


def test_browser_analysis_fetch_failure_is_unscored():
    fetched = {
        "valid": False, "success": False, "url": "http://127.0.0.1/",
        "error": "SSRF protection blocked", "failure_category": "ssrf_blocked",
        "indicators": [], "url_model": {}, "metadata": {},
    }
    with patch("src.browser_analysis.analyze_url", return_value=fetched):
        result = analyze_browser_url("http://127.0.0.1/")
    assert result["fetch_success"] is False
    assert result["advertisement_analysis"]["final_score"] is None


def test_browser_analysis_unavailable_model_remains_separate():
    fetched = {
        "valid": True, "success": True, "url": "https://example.test/",
        "analysis_mode": "live_fetch",
        "final_url": "https://example.test/", "title": "Page",
        "extracted_text": "Normal bank account information.", "html_content": "<p>Normal bank account information.</p>",
        "redirect_history": [{"from": "https://example.test/", "to": "https://www.example.test/", "status": 302}],
        "metadata": {"redirects": 1}, "indicators": [],
        "url_model": {"available": False, "error": "model unavailable"},
    }
    with patch("src.browser_analysis.analyze_url", return_value=fetched):
        result = analyze_browser_url("https://example.test/")
    assert result["redirects"] == 1
    assert result["url_model"]["available"] is False
    assert result["advertisement_analysis"]["final_score"] is not None


def test_mcp_tool_masks_internal_error_and_query_secret():
    import mcp_server

    with patch("mcp_server.analyze_browser_url", side_effect=RuntimeError("failed https://x/?token=secret")):
        result = mcp_server.inspect_financial_url("https://example.test/?token=secret")
    assert result["failure_category"] == "analysis_error"
    assert "secret" not in str(result)
    assert result["advertisement_analysis"]["final_score"] is None
