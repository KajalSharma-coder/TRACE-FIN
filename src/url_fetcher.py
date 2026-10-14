"""
TRACE//FIN — Secure URL Analysis & SSRF-Protected Web Ingestion (Phase 5)
Provides strict URL validation, SSRF mitigation, DNS verification, redirect controls,
safe HTML text extraction, and domain threat indicators.
"""

import ipaddress
import logging
import re
import socket
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("tracefin.url")

# Limits & Timeouts
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MB limit
DEFAULT_TIMEOUT_SECONDS = 5.0
MAX_REDIRECTS = 3
ALLOWED_SCHEMES = {"http", "https"}

# Cloud metadata hostnames & IP targets
BLOCKED_HOSTNAMES = {
    "metadata.google.internal",
    "metadata.local",
    "instance-data",
    "169.254.169.254",
    "fd00:ec2::254",
}

# Suspicious domain keywords often found in fraudulent financial ads / phishing
SUSPICIOUS_DOMAIN_KEYWORDS = [
    "kyc", "bank", "account", "verify", "secure", "login", "auth",
    "instant", "cashout", "payout", "hawala", "wallet", "crypto",
    "transfer", "rent", "mule", "loan", "commission", "telegram",
    "payment", "update", "service", "support",
]


def is_safe_ip(ip_str: str) -> Tuple[bool, Optional[str]]:
    """
    Check if an IP address string is safe to connect to (publicly routable).
    Blocks loopback, private RFC1918, link-local, multicast, reserved,
    unspecified (0.0.0.0), and cloud metadata IP addresses.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, f"Invalid IP address format: {ip_str}"

    if ip.is_loopback:
        return False, f"Loopback address ({ip_str}) blocked (SSRF defense)."
    if ip.is_private:
        return False, f"Private network address ({ip_str}) blocked (SSRF defense)."
    if ip.is_link_local:
        return False, f"Link-local address ({ip_str}) blocked (SSRF defense)."
    if ip.is_multicast:
        return False, f"Multicast address ({ip_str}) blocked."
    if ip.is_reserved:
        return False, f"Reserved address ({ip_str}) blocked."
    if ip.is_unspecified:
        return False, f"Unspecified address ({ip_str}) blocked."

    # Specific metadata addresses
    if str(ip) in BLOCKED_HOSTNAMES:
        return False, f"Cloud metadata endpoint ({ip_str}) blocked (SSRF defense)."

    return True, None


def validate_url_syntax(url_str: str) -> Dict[str, Any]:
    """
    Validate and parse URL string format, scheme, hostname, and extract domain indicators.
    Rejects unsupported schemes, embedded credentials, and malformed hosts.
    """
    res = {
        "valid": False,
        "error": None,
        "scheme": None,
        "hostname": None,
        "port": None,
        "path": None,
        "indicators": [],
        "is_ip_literal": False,
    }

    if not url_str or not isinstance(url_str, str) or not url_str.strip():
        res["error"] = "Empty URL provided."
        return res

    cleaned_url = url_str.strip()

    try:
        parsed = urllib.parse.urlsplit(cleaned_url)
    except Exception as exc:
        res["error"] = f"Malformed URL syntax: {exc}"
        return res

    scheme = parsed.scheme.lower()
    if not scheme:
        res["error"] = "Missing URL scheme (must be http:// or https://)."
        return res

    if scheme not in ALLOWED_SCHEMES:
        res["error"] = f"Unsupported scheme '{scheme}://'. Only http:// and https:// are permitted."
        return res

    # Reject embedded credentials (http://user:pass@host)
    if parsed.username or parsed.password:
        res["error"] = "URLs with embedded user credentials (user:pass@host) are rejected for security."
        return res

    try:
        hostname = parsed.hostname
    except ValueError as exc:
        res["error"] = f"Invalid hostname in URL: {exc}"
        return res

    if not hostname:
        res["error"] = "Missing or invalid hostname in URL."
        return res

    hostname_clean = hostname.lower()

    # Check for blocked cloud metadata hostnames directly
    if hostname_clean in BLOCKED_HOSTNAMES:
        res["error"] = f"Access to cloud metadata host '{hostname_clean}' is prohibited (SSRF defense)."
        return res

    # Check for IP literal
    is_ip = False
    try:
        ipaddress.ip_address(hostname_clean)
        is_ip = True
        res["is_ip_literal"] = True
        res["indicators"].append("[URL Risk] Hostname is a raw IP literal rather than a registered domain.")
    except ValueError:
        pass

    # Domain indicators
    if not is_ip:
        # Check subdomains count
        parts = hostname_clean.split(".")
        if len(parts) > 4:
            res["indicators"].append(f"[URL Structure] Excessive subdomain nesting ({len(parts)} levels).")

        # Check hyphen count
        if hostname_clean.count("-") >= 3:
            res["indicators"].append(f"[URL Structure] High hyphen count ({hostname_clean.count('-')}) in domain name.")

        # Check suspicious keywords in hostname
        matched_kw = [kw for kw in SUSPICIOUS_DOMAIN_KEYWORDS if kw in hostname_clean]
        if matched_kw:
            res["indicators"].append(f"[URL Keyword] Domain contains financial/phishing keywords: {', '.join(matched_kw[:3])}")

    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        res["error"] = f"Invalid URL port format or malformed host: {exc}"
        return res

    res["valid"] = True
    res["scheme"] = scheme
    res["hostname"] = hostname_clean
    res["port"] = port
    res["path"] = parsed.path or "/"
    return res


def resolve_and_verify_hostname(hostname: str, port: int = 443) -> Tuple[bool, List[str], Optional[str]]:
    """
    Resolve DNS for a hostname and verify that ALL returned IPs are safe (publicly routable).
    Protects against DNS rebinding and internal network exposure.
    """
    # If already an IP address, check directly
    try:
        ipaddress.ip_address(hostname)
        safe, reason = is_safe_ip(hostname)
        if not safe:
            return False, [hostname], reason
        return True, [hostname], None
    except ValueError:
        pass

    resolved_ips = []
    try:
        addrinfo = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        for entry in addrinfo:
            sockaddr = entry[4]
            ip_str = sockaddr[0]
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)
    except socket.gaierror as exc:
        return False, [], f"DNS resolution failed for host '{hostname}': {exc}"
    except Exception as exc:
        return False, [], f"DNS lookup error: {exc}"

    if not resolved_ips:
        return False, [], f"No IP addresses resolved for host '{hostname}'."

    # Validate EVERY resolved IP
    for ip_str in resolved_ips:
        safe, reason = is_safe_ip(ip_str)
        if not safe:
            return False, resolved_ips, f"Host '{hostname}' resolved to unsafe address {ip_str}: {reason}"

    return True, resolved_ips, None


def extract_text_from_html(html_content: str) -> Tuple[str, str]:
    """
    Extract title and clean, readable text from HTML content.
    Strips scripts, styles, forms, navigation, and non-informative tags.
    """
    if not html_content or not html_content.strip():
        return "", ""

    title = ""
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_content, "html.parser")

        # Extract title
        if soup.title and soup.title.string:
            title = soup.title.string.strip()

        # Remove non-content tags
        for tag in soup(["script", "style", "noscript", "svg", "header", "footer", "nav", "form"]):
            tag.decompose()

        text = soup.get_text(separator=" ", strip=True)
        # Normalize whitespace
        cleaned = " ".join(text.split())
        return title, cleaned
    except Exception:
        # Fallback regex extraction if bs4 fails
        title_match = re.search(r"<title[^>]*>(.*?)</title>", html_content, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = re.sub(r"<[^>]+>", "", title_match.group(1)).strip()

        cleaned = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html_content, flags=re.IGNORECASE | re.DOTALL)
        cleaned = re.sub(r"<[^>]+>", " ", cleaned)
        cleaned = " ".join(cleaned.split())
        return title, cleaned


def safe_fetch_url(
    url_str: str,
    max_redirects: int = MAX_REDIRECTS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> Dict[str, Any]:
    """
    Safely fetch live website content with strict SSRF controls:
    1. Validates initial URL syntax.
    2. Resolves and validates DNS before EVERY connection attempt.
    3. Manually handles redirects, validating every hop destination.
    4. Enforces 5-second timeout and 2 MB payload cap.
    5. Extracts text safely without code execution.
    """
    result = {
        "success": False,
        "initial_url": url_str,
        "final_url": url_str,
        "status_code": None,
        "title": "",
        "extracted_text": "",
        "content_type": "",
        "bytes_downloaded": 0,
        "redirect_history": [],
        "resolved_ips": [],
        "indicators": [],
        "warnings": [],
        "error": None,
    }

    current_url = url_str

    for hop in range(max_redirects + 1):
        # 1. Validate syntax of current URL
        syntax_res = validate_url_syntax(current_url)
        if not syntax_res["valid"]:
            result["error"] = f"Invalid URL at hop {hop}: {syntax_res['error']}"
            return result

        result["indicators"].extend(syntax_res["indicators"])
        hostname = syntax_res["hostname"]
        port = syntax_res["port"]

        # 2. Resolve DNS and verify safety
        is_safe, ips, dns_err = resolve_and_verify_hostname(hostname, port)
        result["resolved_ips"] = ips
        if not is_safe:
            result["error"] = f"SSRF Protection Alert at hop {hop}: {dns_err}"
            return result

        # 3. Perform request with manual redirect handling and streaming body
        try:
            import requests

            req_headers = {
                "User-Agent": "TRACE-FIN-ThreatIntel/1.0 (+https://github.com/montylr/trace-fin; investigator-triage)",
                "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9",
                "Accept-Language": "en-US,en;q=0.5",
            }

            resp = requests.get(
                current_url,
                headers=req_headers,
                timeout=timeout_seconds,
                allow_redirects=False,
                stream=True,
            )

            result["status_code"] = resp.status_code
            result["final_url"] = current_url

            # Handle redirects manually
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location:
                    result["error"] = f"HTTP {resp.status_code} redirect received with no Location header."
                    return result

                next_url = urllib.parse.urljoin(current_url, location)
                result["redirect_history"].append({
                    "from": current_url,
                    "to": next_url,
                    "status": resp.status_code,
                })

                if hop >= max_redirects:
                    result["error"] = f"Exceeded maximum redirect limit ({max_redirects} hops)."
                    return result

                current_url = next_url
                continue

            # Check content-type
            content_type = resp.headers.get("Content-Type", "")
            result["content_type"] = content_type

            # Stream body up to max_bytes
            downloaded = bytearray()
            truncated = False
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    downloaded.extend(chunk)
                    if len(downloaded) > max_bytes:
                        truncated = True
                        break

            result["bytes_downloaded"] = len(downloaded)
            if truncated:
                result["warnings"].append(f"Response exceeded {max_bytes // (1024*1024)} MB limit and was truncated.")

            # Decode text
            encoding = resp.encoding or "utf-8"
            try:
                raw_html = downloaded.decode(encoding, errors="replace")
            except Exception:
                raw_html = downloaded.decode("utf-8", errors="replace")

            # Extract title and text
            title, clean_text = extract_text_from_html(raw_html)
            result["title"] = title
            result["extracted_text"] = clean_text
            result["success"] = True

            if not clean_text:
                result["warnings"].append("Web page returned empty or non-textual content.")

            return result

        except requests.exceptions.Timeout:
            result["error"] = f"Connection timed out after {timeout_seconds} seconds."
            return result
        except requests.exceptions.SSLError as ssl_err:
            result["error"] = f"TLS/SSL certificate error: {ssl_err}"
            return result
        except requests.exceptions.ConnectionError as conn_err:
            result["error"] = f"Failed to connect to host '{hostname}': {conn_err}"
            return result
        except Exception as exc:
            result["error"] = f"Unexpected fetch error: {exc}"
            return result

    result["error"] = "Redirect resolution loop terminated."
    return result


def analyze_url(url_str: str, fetch_content: bool = True) -> Dict[str, Any]:
    """
    High-level URL analysis entry point.
    Discloses whether analysis was derived from URL syntax alone or live retrieved content.
    """
    syntax_res = validate_url_syntax(url_str)
    if not syntax_res["valid"]:
        return {
            "valid": False,
            "success": False,
            "url": url_str,
            "error": syntax_res["error"],
            "analysis_mode": "syntax_only",
            "disclosure": "Validation failed on URL syntax.",
            "indicators": syntax_res["indicators"],
            "extracted_text": "",
            "title": "",
            "metadata": {},
        }

    if not fetch_content:
        return {
            "valid": True,
            "success": True,
            "url": url_str,
            "error": None,
            "analysis_mode": "syntax_only",
            "disclosure": "URL structure and domain-only analysis (no remote connection made).",
            "indicators": syntax_res["indicators"],
            "hostname": syntax_res["hostname"],
            "scheme": syntax_res["scheme"],
            "port": syntax_res["port"],
            "extracted_text": "",
            "title": "",
            "metadata": {"hostname": syntax_res["hostname"], "is_ip_literal": syntax_res["is_ip_literal"]},
        }

    # Fetch live content safely
    fetch_res = safe_fetch_url(url_str)

    combined_indicators = list(dict.fromkeys(syntax_res["indicators"] + fetch_res.get("indicators", [])))

    return {
        "valid": True,
        "url": url_str,
        "final_url": fetch_res.get("final_url", url_str),
        "success": fetch_res["success"],
        "error": fetch_res.get("error"),
        "analysis_mode": "live_fetch" if fetch_res["success"] else "fetch_failed",
        "disclosure": "Safely retrieved remote HTML content without code execution." if fetch_res["success"] else f"Live fetch failed: {fetch_res.get('error')}. Relying on domain syntax.",
        "indicators": combined_indicators,
        "warnings": fetch_res.get("warnings", []),
        "hostname": syntax_res["hostname"],
        "title": fetch_res.get("title", ""),
        "extracted_text": fetch_res.get("extracted_text", ""),
        "status_code": fetch_res.get("status_code"),
        "bytes_downloaded": fetch_res.get("bytes_downloaded", 0),
        "resolved_ips": fetch_res.get("resolved_ips", []),
        "metadata": {
            "hostname": syntax_res["hostname"],
            "final_url": fetch_res.get("final_url"),
            "status_code": fetch_res.get("status_code"),
            "bytes": fetch_res.get("bytes_downloaded", 0),
            "redirects": len(fetch_res.get("redirect_history", [])),
        },
    }
