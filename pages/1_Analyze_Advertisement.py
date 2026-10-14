"""
TRACE//FIN — Analyze Advertisement Page
Dedicated investigator analysis workflow for suspicious financial advertisements (Phase 3 Dual-Engine).
Combines Phase 2 deterministic heuristic detection with Phase 3 TF-IDF + Logistic Regression ML baseline.
"""

import streamlit as st

from config import APP_NAME
from src.database import init_db, insert_record, get_record, generate_record_id
from src.detector import analyze_ad
from src.ml_model import predict_ad_ml, compare_rule_and_ml, get_model_metrics
from src.sample_data import seed_demo_data
from src.ui_components import (
    inject_global_css, render_sidebar, render_demo_banner,
    render_record_detail, render_disclaimer, render_ml_badge,
    render_consensus_card,
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
st.caption("Dual-Engine Threat Intelligence: Explainable Heuristic Rules (Phase 2) + Supervised ML Classifier (Phase 3)")
render_demo_banner()

# ── Session state ──────────────────────────────────────────────────────
if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None
if "ml_result" not in st.session_state:
    st.session_state.ml_result = None
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
        "Examples:\n"
        "• 'Selling fully KYC verified HDFC account. Call now. Acc holder: Rohan Singh'\n"
        "• 'Rent your bank account for 10k/month. Send details to Pooja Jain. Acc: 61641030277, IFSC: ICIC0475599'\n"
        "• 'Bank accounts for sale, no KYC required, contact Telegram @seller'\n"
        "• 'Work from home: receive transfers into your personal account and keep 10% commission'\n"
        "• 'Vendor payment details: Rohan Kumar, Bank: HDFC, Acc: 66562328946, IFSC: HDFC0437589'"
    ),
    key="ad_text_input",
    label_visibility="collapsed",
)

# Character count & validation stats
char_count = len(ad_text) if ad_text else 0
word_count = len(ad_text.split()) if ad_text else 0
st.caption(f"Input metrics: **{char_count:,}** characters · **{word_count:,}** words")

# Action buttons
btn_col1, btn_col2, _ = st.columns([1.3, 1, 3])

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
    st.session_state.ml_result = None
    st.session_state.saved_record_id = None
    st.rerun()

# ── Handle Analysis ───────────────────────────────────────────────────
if analyze_clicked:
    if not ad_text or not ad_text.strip():
        st.error("⚠ Validation Error: Advertisement text cannot be empty. Please enter or paste text to analyze.")
    else:
        with st.spinner("Executing dual-engine detection (rule heuristic + ML classifier)…"):
            # 1. Phase 2 Explainable Rule-Based Analyzer
            rule_result = analyze_ad(ad_text.strip())

            # 2. Phase 3 Machine Learning Inference
            ml_result = predict_ad_ml(ad_text.strip())

        # Save to database with Dual-Engine attributes
        record_id = generate_record_id()
        analysis_mode = "dual_engine" if ml_result.get("available") else "rule_based"

        record = {
            "record_id": record_id,
            "ad_text": ad_text.strip(),
            "analysis_mode": analysis_mode,
            "risk_score": rule_result["risk_score"],
            "risk_level": rule_result["risk_level"],
            "matched_categories": rule_result["matched_categories"],
            "evidence": rule_result["evidence"],
            "urls": rule_result["urls"],
            "emails": rule_result["emails"],
            "phone_numbers": rule_result["phone_numbers"],
            "payment_identifiers": rule_result["payment_identifiers"],
            "review_required": rule_result["review_required"],
            "review_recommendation": rule_result.get("review_recommendation", "Review required"),
            "investigation_status": "Open",
            "is_synthetic": False,
            "ml_prediction": ml_result.get("risk_label"),
            "ml_confidence": ml_result.get("confidence"),
            "ml_high_risk_score": ml_result.get("high_risk_score"),
            "ml_model_version": ml_result.get("model_version"),
        }
        saved_id = insert_record(record)

        st.session_state.analysis_result = rule_result
        st.session_state.ml_result = ml_result
        st.session_state.saved_record_id = saved_id
        st.success(f"✓ Dual-engine analysis complete. Record persisted as **{saved_id}** with status **Open**.")

# ── Display Results ────────────────────────────────────────────────────
if st.session_state.analysis_result and st.session_state.saved_record_id:
    record_id = st.session_state.saved_record_id
    saved_record = get_record(record_id)

    st.markdown("---")
    st.markdown(
        '<div class="demo-banner">◆ DUAL-ENGINE INTELLIGENCE DOSSIER — '
        'Rule Heuristics & Machine Learning Indicators for Investigator Triage. ◆</div>',
        unsafe_allow_html=True,
    )

    if saved_record:
        # Dual-Engine Consensus Banner
        ml_res = st.session_state.ml_result or {}
        render_consensus_card(
            rule_level=saved_record.get("risk_level", "Low"),
            ml_prediction=saved_record.get("ml_prediction"),
            rule_score=saved_record.get("risk_score", 0),
            ml_confidence=saved_record.get("ml_confidence"),
        )

        tab_dossier, tab_ml_diagnostics = st.tabs([
            "📋 Case Dossier & Heuristic Evidence",
            "⚡ ML Classifier Diagnostics",
        ])

        with tab_dossier:
            render_record_detail(saved_record)

        with tab_ml_diagnostics:
            st.markdown('<div class="section-header">Machine Learning Baseline Diagnostics</div>',
                        unsafe_allow_html=True)

            if ml_res.get("available"):
                ml_c1, ml_c2, ml_c3 = st.columns(3)
                with ml_c1:
                    st.markdown("**ML Predicted Class**")
                    st.markdown(render_ml_badge(ml_res.get("risk_label"), ml_res.get("confidence")),
                                unsafe_allow_html=True)
                with ml_c2:
                    st.markdown("**High-Risk Decision Score**")
                    hrs = ml_res.get("high_risk_score")
                    st.markdown(f"### {hrs:.4f}" if hrs is not None else "—")
                    st.caption("Raw Logistic Regression decision probability for positive class")
                with ml_c3:
                    st.markdown("**Model Version & Architecture**")
                    st.write(f"`{ml_res.get('model_version', 'N/A')}`")
                    st.caption("TF-IDF Vectorizer (1,2-grams) + Logistic Regression")

                # Active vocabulary signals
                st.markdown("**Influential Input Vocabulary Signals**")
                signals = ml_res.get("top_signals", [])
                if signals:
                    sig_cols = st.columns(min(len(signals), 4))
                    for idx, sig in enumerate(signals[:4]):
                        with sig_cols[idx]:
                            dir_color = "#f97316" if sig["direction"] == "High Risk" else "#22c55e"
                            st.markdown(
                                f"""
                                <div style="background: rgba(30, 41, 59, 0.7); border: 1px solid rgba(100, 116, 139, 0.3); border-radius: 6px; padding: 0.6rem 0.8rem;">
                                    <div style="font-weight: 600; color: #f1f5f9; font-size: 0.88rem;">`{sig['token']}`</div>
                                    <div style="font-size: 0.78rem; color: {dir_color}; margin-top: 0.2rem;">
                                        {sig['direction']} ({sig['weight']:+.3f})
                                    </div>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )
                else:
                    st.caption("No strong vocabulary overlaps detected with training lexicon.")

                # Scientific limitations box
                st.markdown(
                    f"""
                    <div class="disclaimer">
                        <strong>Model Interpretability Note:</strong> {ml_res.get('disclaimer')}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                # Show Training Metadata & Metrics
                metrics = get_model_metrics()
                if metrics:
                    with st.expander("📊 View Model Training Metrics & Test-Split Evaluation"):
                        st.json(metrics)

            else:
                st.warning(f"⚠ {ml_res.get('error', 'ML model not available.')}")
                st.info("Execute `python scripts/train_model.py` to fit and generate the model artifact.")

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
                st.session_state.ml_result = None
                st.session_state.saved_record_id = None
                st.rerun()
    else:
        st.error(f"Error: Record {record_id} could not be retrieved from the database.")

# ── Empty state guidance ──────────────────────────────────────────────
if not st.session_state.analysis_result:
    st.markdown("---")
    st.markdown(
        '<div class="card">'
        "<strong>Dual-Engine Threat Intelligence Architecture</strong><br><br>"
        "<strong>1. Explainable Rule-Based Heuristic Engine (Phase 2):</strong><br>"
        "• 5 modular categories: Account/Card Sale, KYC Evasion, Account Rental / Mule Recruitment, Suspicious Solicitation, Urgency/Secrecy.<br>"
        "• Deterministic score (0–100) mapped to standardized tiers (Low, Medium, High, Critical).<br>"
        "• Context-aware false positive protection for bank educational guidelines.<br><br>"
        "<strong>2. Supervised ML Classifier Baseline (Phase 3):</strong><br>"
        "• Scikit-learn Pipeline with sublinear TF-IDF n-grams (1,2-grams) and Logistic Regression.<br>"
        "• Trained on validated financial advertisement text (`data/back.dataset.csv`).<br>"
        "• Provides independent statistical classification alongside heuristic evidence.<br>"
        "• <em>Zero PII usage: Banking identifiers and account digits are strictly excluded.</em>"
        "</div>",
        unsafe_allow_html=True,
    )

render_disclaimer()
