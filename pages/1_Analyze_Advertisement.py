"""
TRACE//FIN — Analyze Advertisement Page
Dedicated investigator analysis workflow for suspicious financial advertisements.
"""

import streamlit as st

from config import APP_NAME
from src.database import init_db, insert_record, get_record, generate_record_id
from src.demo_analyzer import analyze_ad
from src.sample_data import seed_demo_data
from src.ui_components import (
    inject_global_css, render_sidebar, render_demo_banner,
    render_record_detail, render_disclaimer,
)

# ── Page Config ────────────────────────────────────────────────────────
st.set_page_config(
    page_title=f"{APP_NAME} — Analyze Advertisement",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()
seed_demo_data()
inject_global_css()
render_sidebar()

# ── Header ─────────────────────────────────────────────────────────────
st.markdown("# 🔍 Analyze Financial Advertisement")
st.caption("Submit suspicious advertisement, post, or message text for multi-signal triage")
render_demo_banner()

# ── Session state ──────────────────────────────────────────────────────
if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None
if "saved_record_id" not in st.session_state:
    st.session_state.saved_record_id = None

# ── Input Form ─────────────────────────────────────────────────────────
st.markdown('<div class="section-header">Advertisement Content Intake</div>',
            unsafe_allow_html=True)

ad_text = st.text_area(
    "Advertisement or Post Content",
    height=200,
    placeholder=(
        "Paste the raw text of a financial advertisement, forum post, or chat message here…\n\n"
        "Example:\n"
        "🔥 BANK ACCOUNTS FOR SALE 🔥\n"
        "Current accounts and savings accounts available. No KYC required!\n"
        "Guaranteed instant access. Contact on Telegram @findeals_example\n"
        "Contact: +91-98765-43210"
    ),
    key="ad_text_input",
    label_visibility="collapsed",
)

# Character count & validation stats
char_count = len(ad_text) if ad_text else 0
word_count = len(ad_text.split()) if ad_text else 0
st.caption(f"Input metrics: **{char_count:,}** characters · **{word_count:,}** words")

# Action buttons
btn_col1, btn_col2, _ = st.columns([1.2, 1, 3])

with btn_col1:
    analyze_clicked = st.button(
        "🔍 Analyze Advertisement",
        type="primary",
        use_container_width=True,
    )

with btn_col2:
    clear_clicked = st.button(
        "✕ Clear Input",
        use_container_width=True,
    )

# ── Handle Clear ───────────────────────────────────────────────────────
if clear_clicked:
    st.session_state.analysis_result = None
    st.session_state.saved_record_id = None
    st.rerun()

# ── Handle Analysis ───────────────────────────────────────────────────
if analyze_clicked:
    if not ad_text or not ad_text.strip():
        st.error("⚠ Validation Error: Advertisement text cannot be empty. Please enter or paste text to analyze.")
    else:
        with st.spinner("Executing rule-based pattern triage and indicator extraction…"):
            result = analyze_ad(ad_text.strip())

        # Save to database
        record_id = generate_record_id()
        record = {
            "record_id": record_id,
            "ad_text": ad_text.strip(),
            "analysis_mode": "demo",
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
            "matched_categories": result["matched_categories"],
            "evidence": result["evidence"],
            "urls": result["urls"],
            "phone_numbers": result["phone_numbers"],
            "payment_identifiers": result["payment_identifiers"],
            "review_required": result["review_required"],
            "review_recommendation": result.get("review_recommendation", "Review required"),
            "investigation_status": "Open",
            "is_synthetic": False,
        }
        saved_id = insert_record(record)

        st.session_state.analysis_result = result
        st.session_state.saved_record_id = saved_id
        st.success(f"✓ Analysis complete. Record persisted to database as **{saved_id}** with status **Open**.")

# ── Display Results ────────────────────────────────────────────────────
if st.session_state.analysis_result and st.session_state.saved_record_id:
    record_id = st.session_state.saved_record_id

    st.markdown("---")
    st.markdown(
        '<div class="demo-banner">◆ DEMO ANALYSIS RESULT — '
        'Pattern-based scoring for demonstration only. Not a probability of criminal activity. ◆</div>',
        unsafe_allow_html=True,
    )

    # Fetch the saved record for full detail display
    saved_record = get_record(record_id)
    if saved_record:
        render_record_detail(saved_record)

        # Investigator Navigation
        st.markdown('<div class="section-header">Next Steps</div>', unsafe_allow_html=True)
        nav_col1, nav_col2, _ = st.columns([1.5, 1.2, 2.5])
        with nav_col1:
            if st.button("📋 Open in Investigation Cases", use_container_width=True):
                st.session_state["selected_case_id"] = record_id
                st.switch_page("pages/2_Investigation_Cases.py")
        with nav_col2:
            if st.button("🔍 Analyze Another Ad", use_container_width=True):
                st.session_state.analysis_result = None
                st.session_state.saved_record_id = None
                st.rerun()
    else:
        st.error(f"Error: Record {record_id} could not be retrieved from the database.")

# ── Empty state guidance ──────────────────────────────────────────────
if not st.session_state.analysis_result:
    st.markdown("---")
    st.markdown(
        '<div class="card">'
        "<strong>How the Intake & Triage Workflow Operates</strong><br><br>"
        "1. <strong>Intake:</strong> Paste raw advertisement, social media post, or forum text in the editor above.<br>"
        "2. <strong>Pattern Triage:</strong> The analyzer inspects language patterns (account sales, card sales, KYC bypass claims, unusual payment requests).<br>"
        "3. <strong>Entity Extraction:</strong> Structured indicators including URLs, contact phone numbers, and payment handles (e.g. UPI) are extracted.<br>"
        "4. <strong>Case Generation:</strong> Results are automatically saved to persistent SQLite storage under a tracking ID (e.g. <code>TF-XXXXXXXX</code>).<br>"
        "5. <strong>Human Review:</strong> Investigators can open the case file in Case Management to review evidence, change statuses, and track escalation.<br><br>"
        "<em>Phase 1 Note: Uses deterministic pattern-matching. ML scoring, OCR, and relation intelligence will be integrated in subsequent phases.</em>"
        "</div>",
        unsafe_allow_html=True,
    )

render_disclaimer()
