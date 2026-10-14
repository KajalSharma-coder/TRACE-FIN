"""
TRACE//FIN — Unit & Security Tests for Secure URL Analysis (Phase 5)
"""

import os
import sys
import socket
from unittest.mock import MagicMock, patch
import pytest

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.url_fetcher import (
    validate_url_syntax,
    is_safe_ip,
    resolve_and_verify_hostname,
    extract_text_from_html,
    safe_fetch_url,
    analyze_url,
    BLOCKED_HOSTNAMES,
)


# ── 1. URL Syntax & Scheme Validation ──────────────────────────────────

def test_validate_url_syntax_valid_http_https():
    res_https = validate_url_syntax("https://example.com/ad/123")
    assert res_https["valid"] is True
    assert res_https["scheme"] == "https"
    assert res_https["hostname"] == "example.com"
    assert res_https["port"] == 443

    res_http = validate_url_syntax("http://bank-offer.org:8080/path")
    assert res_http["valid"] is True
    assert res_http["scheme"] == "http"
    assert res_http["hostname"] == "bank-offer.org"
    assert res_http["port"] == 8080


def test_validate_url_syntax_empty():
    assert validate_url_syntax("")["valid"] is False
    assert validate_url_syntax("   ")["valid"] is False
    assert validate_url_syntax(None)["valid"] is False


def test_validate_url_syntax_unsupported_schemes():
    unsupported = [
        "file:///etc/passwd",
        "ftp://ftp.example.com/leak.txt",
        "javascript:alert(1)",
        "data:text/html,<h1>phish</h1>",
        "gopher://gopher.example.com",
    ]
    for url in unsupported:
        res = validate_url_syntax(url)
        assert res["valid"] is False
        assert "Unsupported scheme" in res["error"] or "Only http://" in res["error"]


def test_validate_url_syntax_embedded_credentials():
    res = validate_url_syntax("https://admin:secret123@bank.example.com/transfer")
    assert res["valid"] is False
    assert "embedded user credentials" in res["error"].lower()


def test_validate_url_syntax_blocked_metadata_hostnames():
    for blocked in BLOCKED_HOSTNAMES:
        target = f"[{blocked}]" if ":" in blocked else blocked
        res = validate_url_syntax(f"http://{target}/latest/meta-data/")
        assert res["valid"] is False
        assert "prohibited" in res["error"].lower() or "blocked" in res["error"].lower()


# ── 2. IP Safety & SSRF Defenses ───────────────────────────────────────

def test_is_safe_ip_loopback():
    for loopback in ["127.0.0.1", "127.0.1.1", "127.100.200.1", "::1"]:
        safe, reason = is_safe_ip(loopback)
        assert safe is False
        assert "Loopback" in reason or "SSRF" in reason


def test_is_safe_ip_private():
    private_ips = [
        "10.0.0.1", "10.254.254.254",
        "172.16.0.1", "172.31.255.255",
        "192.168.0.1", "192.168.1.254",
        "fc00::1",
    ]
    for priv in private_ips:
        safe, reason = is_safe_ip(priv)
        assert safe is False
        assert "Private" in reason or "SSRF" in reason


def test_is_safe_ip_link_local_and_cloud_metadata():
    for ip in ["169.254.169.254", "169.254.1.1", "fe80::1"]:
        safe, reason = is_safe_ip(ip)
        assert safe is False


def test_is_safe_ip_unspecified_and_multicast():
    assert is_safe_ip("0.0.0.0")[0] is False
    assert is_safe_ip("224.0.0.1")[0] is False


def test_is_safe_ip_public_routable():
    # Public IPs should be deemed safe
    for pub in ["8.8.8.8", "1.1.1.1", "93.184.216.34"]:
        safe, reason = is_safe_ip(pub)
        assert safe is True
        assert reason is None


# ── 3. DNS Resolution Verification ─────────────────────────────────────

def test_resolve_and_verify_hostname_safe():
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        safe, ips, err = resolve_and_verify_hostname("example.com")
        assert safe is True
        assert "93.184.216.34" in ips
        assert err is None


def test_resolve_and_verify_hostname_dns_rebinding_ssrf():
    # If a domain resolves to a private IP, it must be blocked!
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
        ]
        safe, ips, err = resolve_and_verify_hostname("rebind-to-localhost.example.com")
        assert safe is False
        assert "unsafe address" in err.lower() or "ssrf" in err.lower()


def test_resolve_and_verify_hostname_dns_failure():
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
        safe, ips, err = resolve_and_verify_hostname("nonexistent-domain-12345.xyz")
        assert safe is False
        assert "DNS resolution failed" in err


# ── 4. HTML Text Extraction ───────────────────────────────────────────

def test_extract_text_from_html():
    raw_html = """
    <!DOCTYPE html>
    <html>
    <head><title>Urgent Bank Account Verification</title></head>
    <body>
        <script>alert('malicious')</script>
        <style>body { color: red; }</style>
        <h1>Sell Your KYC Account Now</h1>
        <p>Earn 10k per month by renting your current account. Contact Telegram @seller</p>
    </body>
    </html>
    """
    title, clean_text = extract_text_from_html(raw_html)
    assert title == "Urgent Bank Account Verification"
    assert "Sell Your KYC Account Now" in clean_text
    assert "Earn 10k per month" in clean_text
    assert "alert('malicious')" not in clean_text
    assert "color: red" not in clean_text


def test_extract_text_from_html_empty():
    assert extract_text_from_html("") == ("", "")
    assert extract_text_from_html(None) == ("", "")


# ── 5. Mocked Safe Fetch & Redirect Control ────────────────────────────

def test_safe_fetch_url_blocks_redirect_to_internal():
    # Test that a 302 redirect pointing to http://127.0.0.1 is caught and blocked!
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]

        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {"Location": "http://127.0.0.1:8000/admin"}

        with patch("requests.get", return_value=mock_resp):
            res = safe_fetch_url("https://example.com/redirect-to-internal")
            assert res["success"] is False
            assert "SSRF" in res["error"] or "blocked" in res["error"].lower()


def test_analyze_url_syntax_only():
    res = analyze_url("https://instant-cashout-kyc-verify.top/login", fetch_content=False)
    assert res["valid"] is True
    assert res["analysis_mode"] == "syntax_only"
    assert len(res["indicators"]) > 0
    assert any("Keyword" in ind or "financial" in ind.lower() for ind in res["indicators"])


# ── 6. End-to-End URL Pipeline & Regression Tests ─────────────────────

from src.analysis_service import (
    run_unified_analysis,
    persist_analysis_record,
    _normalize_urls_list,
    STATUS_SUCCESS,
    STATUS_SYNTAX_ONLY,
    STATUS_EXTRACTION_FAILED,
)
from src.database import _serialize, _deserialize_list, get_record


def test_successful_url_fetch_analyzing_live_content():
    """Test safe URL retrieval and downstream multi-engine analysis."""
    html_sample = """
    <html>
        <head><title>Loan Offer Page</title></head>
        <body>
            <h1>Special Loan Offers</h1>
            <p>Personal loan offers with low interest rates and nominal processing fee as per terms.</p>
        </body>
    </html>
    """
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
        mock_resp.encoding = "utf-8"
        mock_resp.iter_content.return_value = [html_sample.encode("utf-8")]

        with patch("requests.get", return_value=mock_resp):
            url_res = analyze_url("https://legit-bank.example.com/offers", fetch_content=True)
            assert url_res["valid"] is True
            assert url_res["success"] is True
            assert "Personal loan offers" in url_res["extracted_text"]

            # Run unified analysis on extracted text
            analysis = run_unified_analysis(
                text=url_res["extracted_text"],
                source_type="Website URL",
                source_metadata={"final_url": url_res["final_url"]},
                extraction_status=STATUS_SUCCESS,
            )
            assert analysis["has_sufficient_evidence"] is True
            assert analysis["final_verdict"] == "LOW RISK"
            assert analysis["final_score"] == 0
            assert "https://legit-bank.example.com/offers" in analysis["urls"]
            # Ensure no character splitting occurred
            for u in analysis["urls"]:
                assert len(u) > 1


def test_url_fetch_failure_preserves_insufficient_evidence():
    """Test that URL retrieval failure preserves INSUFFICIENT EVIDENCE with clear failure reason."""
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
        url_res = analyze_url("https://dead-domain-unreachable.biz/promo", fetch_content=True)
        assert url_res["valid"] is True
        assert url_res["success"] is False
        assert url_res["error"] is not None

        analysis = run_unified_analysis(
            text=f"URL domain analysis: {url_res['hostname']}",
            source_type="Website URL (Fetch Failed)",
            source_metadata={"final_url": url_res["url"]},
            extraction_status=STATUS_EXTRACTION_FAILED,
            extraction_error=url_res["error"],
        )

        assert analysis["has_sufficient_evidence"] is False
        assert analysis["final_verdict"] == "INSUFFICIENT EVIDENCE"
        assert analysis["final_score"] is None
        assert "Webpage content could not be retrieved" in analysis["explanation"]
        assert analysis["review_required"] is True
        assert "https://dead-domain-unreachable.biz/promo" in analysis["urls"]


def test_legitimate_vs_suspicious_url_content():
    """Verify legitimate banking disclosures score LOW RISK while fraud solicitation scores HIGH RISK."""
    legit_text = (
        "Personal Loan Offers - Low Interest Rates. Apply for pre-approved personal loans "
        "with nominal processing fee applicable as per bank terms. Competitive annual interest rates."
    )
    legit_res = run_unified_analysis(
        text=legit_text,
        source_type="Website URL",
        source_metadata={"final_url": "https://secure-bank.example.com/loans"},
    )
    assert legit_res["final_verdict"] == "LOW RISK"
    assert legit_res["final_score"] == 0
    assert legit_res["consensus_status"] == "Mitigated Legitimate Content"

    suspicious_text = (
        "Urgent! Current Bank Accounts for Sale. Instant delivery of fully activated accounts with debit card, "
        "net banking kit, and OTP bypass. Contact Telegram @mulevendor"
    )
    suspicious_res = run_unified_analysis(
        text=suspicious_text,
        source_type="Website URL",
        source_metadata={"final_url": "https://mule-accounts.example.biz/buy"},
    )
    assert suspicious_res["final_verdict"] == "HIGH RISK"
    assert suspicious_res["final_score"] >= 75
    assert suspicious_res["review_required"] is True


def test_url_character_split_prevention():
    """Verify URLs are preserved as complete strings across extraction, serialization, and storage."""
    url = "https://unverified-fastloan.biz/offer"

    # 1. Normalization helper
    norm_single = _normalize_urls_list(url)
    assert norm_single == [url]
    assert len(norm_single[0]) > 1

    # 2. Heal accidentally iterated characters
    split_chars = list(url)
    healed = _normalize_urls_list(split_chars)
    assert healed == [url]

    # 3. Database serialization / deserialization round-trip
    serialized = _serialize(url)
    deserialized = _deserialize_list(serialized)
    assert deserialized == [url]

    # Raw string in DB deserialization
    raw_deserialized = _deserialize_list(url)
    assert raw_deserialized == [url]

    # Accidental split JSON in DB
    accidental_json = _serialize(split_chars)
    deserialized_accidental = _deserialize_list(accidental_json)
    assert deserialized_accidental == [url]


def test_direct_text_bare_url_handling():
    """Submitting a bare URL directly into text input returns INSUFFICIENT EVIDENCE."""
    bare_url = "https://unverified-fastloan.biz"
    res = run_unified_analysis(text=bare_url, source_type="Direct Text")
    assert res["final_verdict"] == "INSUFFICIENT EVIDENCE"
    assert res["has_sufficient_evidence"] is False
    assert "bare URL" in res["explanation"]
    assert res["urls"] == [bare_url]
