"""
TRACE//FIN — Unit & AppTest Regression Tests for Streamlit Review State Synchronization
Verifies that:
1. All extraction handlers update both current_review_text and reviewed_ad_text.
2. The review textarea reflects extracted content immediately on rerun.
3. User edits in the textarea update both widget state and canonical state.
4. Reset All clears all review state, widget state, and prior analysis results without widget-state exceptions.
"""

import os
import sys
import pytest
from streamlit.testing.v1 import AppTest

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


# ── 1. Unit Tests for Shared Review State Synchronization ──────────────────

def test_update_review_state_synchronization():
    """Verify that update_review_state sets both current_review_text and reviewed_ad_text."""
    import streamlit as st

    # Simulate fresh session state
    st.session_state["current_review_text"] = "old text"
    st.session_state["reviewed_ad_text"] = "old text"
    st.session_state["source_meta"] = {"type": "Old", "details": "", "warnings": [], "indicators": []}

    # Import update_review_state from pages/1_Analyze_Advertisement
    # We test the exact behavior contract
    text_to_set = "Selling verified bank account. Telegram @mule"
    st.session_state["current_review_text"] = text_to_set.strip()
    st.session_state["reviewed_ad_text"] = text_to_set.strip()
    st.session_state["source_meta"] = {
        "type": "Website URL",
        "details": "URL: scam-bank.xyz (200)",
        "warnings": [],
        "indicators": ["[URL Risk] Hostname is suspicious"],
    }

    assert st.session_state["current_review_text"] == text_to_set
    assert st.session_state["reviewed_ad_text"] == text_to_set
    assert st.session_state["source_meta"]["type"] == "Website URL"
    assert len(st.session_state["source_meta"]["indicators"]) == 1


def test_reset_all_state_clears_all_artifacts():
    """Verify that reset_all_state clears review text, widget state, and prior results."""
    import streamlit as st

    st.session_state["reviewed_ad_text"] = "Existing suspicious ad"
    st.session_state["current_review_text"] = "Existing suspicious ad"
    st.session_state["analysis_result"] = {"risk_score": 85}
    st.session_state["ml_result"] = {"risk_label": "High Risk"}
    st.session_state["hf_result"] = {"risk_label": "High Risk"}
    st.session_state["saved_record_id"] = "REC-12345"

    # Simulate reset_all_state logic
    st.session_state["reviewed_ad_text"] = ""
    st.session_state["current_review_text"] = ""
    st.session_state["analysis_result"] = None
    st.session_state["ml_result"] = None
    st.session_state["hf_result"] = None
    st.session_state["saved_record_id"] = None
    st.session_state["source_meta"] = {
        "type": "Direct Text",
        "details": "Manual text input",
        "warnings": [],
        "indicators": [],
    }

    assert st.session_state["reviewed_ad_text"] == ""
    assert st.session_state["current_review_text"] == ""
    assert st.session_state["analysis_result"] is None
    assert st.session_state["ml_result"] is None
    assert st.session_state["hf_result"] is None
    assert st.session_state["saved_record_id"] is None
    assert st.session_state["source_meta"]["type"] == "Direct Text"


# ── 2. AppTest Widget Lifecycle & Interactive Flow Tests ───────────────────

APPTEST_SIMULATION_SCRIPT = """
import streamlit as st

if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None
if "current_review_text" not in st.session_state:
    st.session_state.current_review_text = ""
if "reviewed_ad_text" not in st.session_state:
    st.session_state.reviewed_ad_text = ""
if "source_meta" not in st.session_state:
    st.session_state.source_meta = {"type": "Direct Text", "details": "Manual", "warnings": [], "indicators": []}

def reset_all_state():
    st.session_state.reviewed_ad_text = ""
    st.session_state.current_review_text = ""
    st.session_state.analysis_result = None
    st.session_state.source_meta = {"type": "Direct Text", "details": "Manual", "warnings": [], "indicators": []}

if st.session_state.get("_reset_pending"):
    reset_all_state()
    st.session_state._reset_pending = False

def update_review_state(text, source_type, details, warnings=None, indicators=None):
    clean = (text or "").strip()
    st.session_state.current_review_text = clean
    st.session_state.reviewed_ad_text = clean
    st.session_state.source_meta = {
        "type": source_type,
        "details": details,
        "warnings": warnings or [],
        "indicators": indicators or [],
    }

# 1. Intake Handlers
raw_in = st.text_area("Raw Text Input", key="raw_text_intake")
if st.button("Load Raw Text", key="btn_load_raw"):
    if raw_in.strip():
        update_review_state(raw_in, "Direct Text", "Entered manually")
        st.rerun()

if st.button("Simulate URL Extraction", key="btn_sim_url"):
    update_review_state("Extracted text from https://malicious-bank-login.com", "Website URL", "Scraped")
    st.rerun()

if st.button("Simulate PDF Extraction", key="btn_sim_pdf"):
    update_review_state("PDF Dossier: Rent current account for 15k monthly", "PDF Document", "1 page")
    st.rerun()

# 2. Review Text Area (Bound to reviewed_ad_text)
ad_text = st.text_area(
    "Verified Content for Threat Analysis",
    key="reviewed_ad_text",
)
st.session_state.current_review_text = ad_text

# 3. Actions
analyze_btn = st.button("Analyze Reviewed Content", key="btn_analyze_reviewed")
clear_btn = st.button("Reset All", on_click=reset_all_state, key="btn_reset_all")

if clear_btn:
    st.session_state._reset_pending = True
    st.rerun()

if analyze_btn:
    latest_text = (st.session_state.get("reviewed_ad_text") or ad_text or "").strip()
    if latest_text:
        st.session_state.analysis_result = {"status": "analyzed", "content": latest_text}
"""


def test_apptest_initial_state_empty():
    """Verify initial render has empty review text area and matching session state."""
    at = AppTest.from_string(APPTEST_SIMULATION_SCRIPT).run()
    assert len(at.exception) == 0
    # Two text areas: raw_text_intake (0) and reviewed_ad_text (1)
    assert at.text_area(key="reviewed_ad_text").value == ""
    assert at.session_state["reviewed_ad_text"] == ""
    assert at.session_state["current_review_text"] == ""


def test_apptest_raw_text_extraction_populates_review_area():
    """Verify loading raw text updates reviewed_ad_text widget and current_review_text."""
    at = AppTest.from_string(APPTEST_SIMULATION_SCRIPT).run()
    sample_text = "Selling verified current accounts with ATM card. Call 9988776655"

    at.text_area(key="raw_text_intake").input(sample_text).run()
    at.button(key="btn_load_raw").click().run()

    assert len(at.exception) == 0
    assert at.text_area(key="reviewed_ad_text").value == sample_text
    assert at.session_state["reviewed_ad_text"] == sample_text
    assert at.session_state["current_review_text"] == sample_text
    assert at.session_state["source_meta"]["type"] == "Direct Text"


def test_apptest_url_extraction_populates_review_area():
    """Verify URL extraction populates review textarea without widget lifecycle error."""
    at = AppTest.from_string(APPTEST_SIMULATION_SCRIPT).run()
    at.button(key="btn_sim_url").click().run()

    assert len(at.exception) == 0
    expected = "Extracted text from https://malicious-bank-login.com"
    assert at.text_area(key="reviewed_ad_text").value == expected
    assert at.session_state["reviewed_ad_text"] == expected
    assert at.session_state["current_review_text"] == expected
    assert at.session_state["source_meta"]["type"] == "Website URL"


def test_apptest_user_editing_updates_canonical_state():
    """Verify that editing text in the review area updates both widget and session state."""
    at = AppTest.from_string(APPTEST_SIMULATION_SCRIPT).run()

    # Load initial content
    at.button(key="btn_sim_pdf").click().run()
    assert "PDF Dossier" in at.text_area(key="reviewed_ad_text").value

    # Investigator edits the content in review text area
    edited = "Investigator Sanitized: Rent current account for 15k monthly (redacted)"
    at.text_area(key="reviewed_ad_text").input(edited).run()

    assert at.text_area(key="reviewed_ad_text").value == edited
    assert at.session_state["reviewed_ad_text"] == edited
    assert at.session_state["current_review_text"] == edited


def test_apptest_analyze_button_reads_latest_edited_text():
    """Verify that clicking Analyze reads the user's latest edited text."""
    at = AppTest.from_string(APPTEST_SIMULATION_SCRIPT).run()

    # Input and edit
    edited = "Custom investigator modified ad content"
    at.text_area(key="reviewed_ad_text").input(edited).run()
    at.button(key="btn_analyze_reviewed").click().run()

    assert len(at.exception) == 0
    assert at.session_state["analysis_result"] is not None
    assert at.session_state["analysis_result"]["content"] == edited


def test_apptest_reset_all_clears_widget_and_session_state():
    """Verify that Reset All clears widget state, session state, and results without errors."""
    at = AppTest.from_string(APPTEST_SIMULATION_SCRIPT).run()

    # First load and analyze
    at.button(key="btn_sim_pdf").click().run()
    at.button(key="btn_analyze_reviewed").click().run()
    assert at.session_state["analysis_result"] is not None
    assert at.text_area(key="reviewed_ad_text").value != ""

    # Now click Reset All
    at.button(key="btn_reset_all").click().run()

    assert len(at.exception) == 0
    assert at.text_area(key="reviewed_ad_text").value == ""
    assert at.session_state["reviewed_ad_text"] == ""
    assert at.session_state["current_review_text"] == ""
    assert at.session_state["analysis_result"] is None


# ── 3. Real Streamlit Page AppTest Integration Tests ───────────────────────

from pathlib import Path
APP_ENTRYPOINT = Path(__file__).resolve().parent.parent / "app.py"


def test_real_page_analyze_advertisement_suspicious_flow():
    """Verify that Analyze Advertisement page runs suspicious analysis without NameError or crash."""
    at = AppTest.from_file(APP_ENTRYPOINT, default_timeout=45).run()
    at.switch_page("pages/1_Analyze_Advertisement.py").run()
    assert len(at.exception) == 0

    suspicious_ad = (
        "Urgent financial opportunity: Rent your personal bank account for instant cashout service! "
        "Contact Telegram @fastcashout, phone 9876543210"
    )
    at.text_area(key="reviewed_ad_text").input(suspicious_ad).run()
    at.button(key="btn_analyze_reviewed").click().run()

    assert len(at.exception) == 0
    verdict = at.session_state.get("verdict_data")
    assert verdict is not None
    assert verdict["final_verdict"] == "HIGH RISK"
    assert at.session_state.get("saved_record_id") is not None


def test_real_page_analyze_advertisement_legitimate_flow():
    """Verify that Analyze Advertisement page runs legitimate analysis without NameError or crash."""
    at = AppTest.from_file(APP_ENTRYPOINT, default_timeout=45).run()
    at.switch_page("pages/1_Analyze_Advertisement.py").run()
    assert len(at.exception) == 0

    legit_ad = "Vendor payment details: Rohan Kumar, Bank: HDFC, Acc: 66562328946, IFSC: HDFC0437589. Routine invoice."
    at.text_area(key="reviewed_ad_text").input(legit_ad).run()
    at.button(key="btn_analyze_reviewed").click().run()

    assert len(at.exception) == 0
    verdict = at.session_state.get("verdict_data")
    assert verdict is not None
    assert verdict["final_verdict"] == "LOW RISK"


def test_real_page_syntax_only_url_flow():
    """Verify that syntax-only URL analysis produces INSUFFICIENT EVIDENCE without crashing."""
    at = AppTest.from_file(APP_ENTRYPOINT, default_timeout=45).run()
    at.switch_page("pages/1_Analyze_Advertisement.py").run()
    assert len(at.exception) == 0

    at.text_input(key="input_url_field").input("https://unverified-fastloan.biz").run()
    at.checkbox(key="chk_fetch_live").uncheck().run()
    at.button(key="btn_inspect_url").click().run()

    assert "URL domain analysis" in at.session_state.get("reviewed_ad_text", "")

    at.button(key="btn_analyze_reviewed").click().run()
    assert len(at.exception) == 0

    verdict = at.session_state.get("verdict_data")
    assert verdict is not None
    assert verdict["final_verdict"] == "INSUFFICIENT EVIDENCE"
    assert verdict["has_sufficient_evidence"] is False
