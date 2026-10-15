"""
TRACE//FIN — Image & Screenshot OCR Analysis Page (Phase 4)
Upload advertisement screenshots or images (JPG, PNG, WEBP), extract text locally via
Tesseract OCR, edit/verify extracted text, and run multi-engine threat detection.
Uploaded images are strictly processed in-memory and NEVER persisted to disk.
"""

import streamlit as st
from PIL import Image

from config import APP_NAME
from src.analysis_service import run_unified_analysis, persist_analysis_record, _normalize_urls_list
from src.database import generate_record_id, get_record, init_db, insert_record
from src.detector import analyze_ad, compute_unified_verdict
from src.hf_model import get_hf_model_info, predict_ad_hf
from src.ml_model import get_model_metrics, predict_ad_ml
from src.ocr_engine import extract_text_ocr, is_tesseract_available, is_easyocr_available, validate_image
from src.sample_data import seed_demo_data
from src.ui_components import (
    inject_global_css,
    render_consensus_card,
    render_demo_banner,
    render_disclaimer,
    render_hf_badge,
    render_metric_card,
    render_ml_badge,
    render_record_detail,
    render_risk_badge,
    render_sidebar,
)

# ── Page Config ────────────────────────────────────────────────────────
st.set_page_config(
    page_title=f"{APP_NAME} — Image OCR Analysis",
    page_icon="🖼️",
    layout="wide",
    initial_sidebar_state="expanded",
)

from src.auth import require_authenticated_user
if not require_authenticated_user():
    st.stop()

init_db()
seed_demo_data()
inject_global_css()
render_sidebar()

# ── Header ─────────────────────────────────────────────────────────────
st.markdown("# 🖼️ Image & Screenshot OCR Analysis")
st.caption("Investigative Intake for Social Media Screenshots, Chat Posters, & Digital Advertisement Banners")
render_demo_banner()

# System dependency check banner
ocr_runtime_ok = is_easyocr_available() or is_tesseract_available()
if not ocr_runtime_ok:
    st.warning(
        "No local OCR engine is installed. Image upload and preview remain available. "
        "Install EasyOCR with `pip install -r requirements.txt`, or install system Tesseract as a fallback."
    )

# ── Session State ──────────────────────────────────────────────────────
if "ocr_extracted_text" not in st.session_state:
    st.session_state.ocr_extracted_text = ""
if "ocr_confidence" not in st.session_state:
    st.session_state.ocr_confidence = None
if "image_analyzed_record_id" not in st.session_state:
    st.session_state.image_analyzed_record_id = None
if "image_file_meta" not in st.session_state:
    st.session_state.image_file_meta = None
if "image_verdict_data" not in st.session_state:
    st.session_state.image_verdict_data = None

# ── Image Upload & Processing ──────────────────────────────────────────
st.markdown('<div class="section-header">1. Upload Advertisement Screenshot or Graphic</div>', unsafe_allow_html=True)
st.caption("Supported formats: **JPG, JPEG, PNG, WEBP** · Max file size: **10 MB** · Max dimensions: **8000×8000 px**")

uploaded_file = st.file_uploader(
    "Choose an advertisement image or screenshot",
    type=["jpg", "jpeg", "png", "webp"],
    key="ocr_image_uploader",
    help="Image is processed in volatile memory for OCR extraction and never stored on disk.",
)

col_img_left, col_img_right = st.columns([1, 1])

if uploaded_file is not None:
    val_res = validate_image(uploaded_file)
    if not val_res["valid"]:
        st.error(f"❌ Image Validation Failed: {val_res['error']}")
    else:
        st.session_state.image_file_meta = {
            "name": uploaded_file.name,
            "size_kb": val_res["file_size_kb"],
            "dimensions": val_res["dimensions"],
        }
        with col_img_left:
            st.markdown("##### Image Preview")
            st.image(val_res["image"], caption=f"{uploaded_file.name} ({val_res['dimensions'][0]}×{val_res['dimensions'][1]} px, {val_res['file_size_kb']:.1f} KB)", use_container_width=True)

        with col_img_right:
            st.markdown("##### Optical Character Recognition (OCR)")
            st.caption("Extract text with local EasyOCR (or Tesseract fallback); images are not sent to a cloud service.")

            if st.button("⚡ Extract Text via Local OCR", type="primary", use_container_width=True):
                with st.spinner("Extracting text locally…"):
                    ocr_res = extract_text_ocr(val_res["image"])
                    if ocr_res["available"] and ocr_res["text"].strip():
                        st.session_state.ocr_extracted_text = ocr_res["text"].strip()
                        st.session_state.ocr_confidence = ocr_res.get("confidence")
                        st.success(f"✓ {ocr_res.get('engine', 'OCR')} extracted text with ~{ocr_res.get('confidence', 0):.1f}% average confidence.")
                    else:
                        st.warning(f"⚠️ {ocr_res.get('error', 'No readable text identified in image.')}")
                        st.session_state.ocr_extracted_text = ""

# ── Editable Text Verification ─────────────────────────────────────────
st.markdown('<div class="section-header">2. Verify & Edit Extracted Content</div>', unsafe_allow_html=True)
st.caption("Investigators can correct OCR typos, misread bank numbers, or insert missing contextual phrases before running threat intelligence triage.")

edited_text = st.text_area(
    "Extracted / Corrected Advertisement Text",
    value=st.session_state.ocr_extracted_text,
    height=150,
    placeholder="Extracted OCR text will appear here. You can also paste or manually transcribe advertisement text directly…",
    key="ocr_text_editor",
)

ocr_conf = st.session_state.ocr_confidence
if ocr_conf is not None:
    st.info(f"ℹ️ **OCR Extraction Metric:** Average character recognition confidence: **{ocr_conf:.1f}%**")

run_col1, run_col2, _ = st.columns([1.5, 1, 3])
with run_col1:
    run_analysis_clicked = st.button("🔍 Analyze Text through Detection Engines", type="primary", use_container_width=True)
with run_col2:
    if st.button("✕ Clear All", use_container_width=True):
        st.session_state.ocr_extracted_text = ""
        st.session_state.ocr_confidence = None
        st.session_state.image_analyzed_record_id = None
        st.session_state.image_file_meta = None
        st.session_state.image_verdict_data = None
        st.rerun()

# ── Execute Multi-Engine Analysis ─────────────────────────────────────
if run_analysis_clicked:
    clean_text = (edited_text or "").strip()
    if not clean_text:
        st.error("⚠ Validation Error: Advertisement text is blank. Upload an image and extract text, or type text manually.")
    else:
        with st.spinner("Running Multi-Engine Triage (Rules + TF-IDF ML + DistilBERT)…"):
            analysis = run_unified_analysis(
                text=clean_text,
                source_type="Image OCR",
                source_metadata=st.session_state.image_file_meta,
            )

        saved_id = persist_analysis_record(analysis)
        st.session_state.image_analyzed_record_id = saved_id
        st.session_state.image_verdict_data = analysis
        st.success(f"✓ Analysis complete. Record persisted into investigation database as **{saved_id}** with status **{analysis['investigation_status']}**.")

# ── Display Results ───────────────────────────────────────────────────
if st.session_state.image_analyzed_record_id:
    rec_id = st.session_state.image_analyzed_record_id
    rec = get_record(rec_id)
    if rec:
        verdict = st.session_state.get("image_verdict_data")
        if not verdict:
            verdict = run_unified_analysis(rec.get("ad_text", ""), source_type="Image OCR")

        final_verdict = verdict["final_verdict"]
        final_score = int(verdict["final_score"]) if verdict.get("final_score") is not None else None
        explanation = verdict["explanation"]
        recommendation = verdict["recommendation"]
        status = verdict["investigation_status"]

        if final_verdict == "HIGH RISK":
            v_color = "#ef4444"
            v_bg = "rgba(239, 68, 68, 0.12)"
            v_border = "rgba(239, 68, 68, 0.5)"
            v_icon = "🚨"
        elif final_verdict == "MEDIUM RISK":
            v_color = "#eab308"
            v_bg = "rgba(234, 179, 8, 0.12)"
            v_border = "rgba(234, 179, 8, 0.5)"
            v_icon = "⚠️"
        elif final_verdict == "INSUFFICIENT EVIDENCE":
            v_color = "#94a3b8"
            v_bg = "rgba(148, 163, 184, 0.12)"
            v_border = "rgba(148, 163, 184, 0.5)"
            v_icon = "🔍"
        else:
            v_color = "#22c55e"
            v_bg = "rgba(34, 197, 94, 0.12)"
            v_border = "rgba(34, 197, 94, 0.5)"
            v_icon = "🛡️"

        st.markdown("---")
        st.markdown('<div class="section-header">3. Threat Analysis Dossier & Unified Verdict</div>', unsafe_allow_html=True)

        # ── 1. Prominent Verdict Card ─────────────────────────────────
        score_display = (
            f'{final_score} <span style="font-size: 1.1rem; color: #94a3b8; font-weight: 500;">/ 100</span>'
            if final_score is not None else
            '<span style="font-size: 1.6rem; color: #94a3b8;">N/A</span>'
        )
        st.markdown(
            f"""
            <div style="background: {v_bg}; border: 2px solid {v_border}; border-radius: 10px; padding: 1.5rem 1.8rem; margin: 1rem 0;">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; border-bottom: 1px solid {v_border}; padding-bottom: 1rem; margin-bottom: 1rem;">
                    <div>
                        <span style="font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1.5px; color: #94a3b8; font-weight: 600;">FINAL TRIAGE VERDICT</span>
                        <div style="font-size: 2.2rem; font-weight: 800; color: {v_color}; letter-spacing: 1px; line-height: 1.2;">
                            {v_icon} {final_verdict}
                        </div>
                    </div>
                    <div style="text-align: right;">
                        <span style="font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1.5px; color: #94a3b8; font-weight: 600;">FINAL RISK SCORE</span>
                        <div style="font-size: 2.4rem; font-weight: 800; color: #f8fafc; line-height: 1.2;">
                            {score_display}
                        </div>
                    </div>
                </div>
                <div style="font-size: 1.05rem; color: #f1f5f9; font-weight: 500; line-height: 1.5; margin-bottom: 0.8rem;">
                    {explanation}
                </div>
                <div style="display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; margin-top: 0.5rem; font-size: 0.88rem;">
                    <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(148, 163, 184, 0.3); border-radius: 6px; padding: 0.4rem 0.8rem; color: #cbd5e1;">
                        <strong>Recommended Action:</strong> <span style="color: {v_color}; font-weight: 600;">{recommendation}</span>
                    </div>
                    <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(148, 163, 184, 0.3); border-radius: 6px; padding: 0.4rem 0.8rem; color: #cbd5e1;">
                        <strong>Case Status:</strong> <span style="font-weight: 600;">{status}</span> · Record ID: <code>{rec_id}</code>
                    </div>
                </div>
                <div style="margin-top: 0.8rem; font-size: 0.78rem; color: #94a3b8; font-style: italic;">
                    ⚖️ Decision-support triage verdict. Statistical models and rule heuristics do not definitively prove criminal fraud; all flagged cases require authorized investigator verification.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # ── 2. Key Evidence & Extracted Identifiers Panel ─────────────
        st.markdown('<div class="section-header">Key Evidence & Extracted Identifiers</div>', unsafe_allow_html=True)
        ev_col, id_col = st.columns([1.2, 1])

        with ev_col:
            st.markdown("**Rule Engine Evidence Matches**")
            for item in verdict.get("evidence", []):
                if "[Model Availability]" in str(item):
                    st.warning(str(item))
            matched_rules = verdict.get("matched_rules", [])
            if matched_rules:
                for r in matched_rules:
                    st.markdown(
                        f"""
                        <div style="background: rgba(30, 41, 59, 0.7); border-left: 3px solid #38bdf8; padding: 0.5rem 0.8rem; margin-bottom: 0.5rem; border-radius: 0 4px 4px 0;">
                            <div style="font-size: 0.85rem; font-weight: 600; color: #38bdf8;">
                                {r.get('rule_name', 'Rule Match')} <span style="font-size: 0.75rem; color: #94a3b8;">({r.get('category', 'Category')})</span>
                            </div>
                            <div style="font-size: 0.82rem; color: #e2e8f0; margin-top: 0.2rem;">
                                Triggered by: <code>{r.get('evidence', '')}</code>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            else:
                st.info("ℹ️ **No configured rules matched.** (Statistical models may still detect anomalies; lack of rule match alone does not confirm safety.)")

        with id_col:
            st.markdown("**Extracted Contact & Banking Identifiers**")
            id_urls = _normalize_urls_list(verdict.get("urls", []))
            id_emails = _normalize_urls_list(verdict.get("emails", []))
            id_phones = _normalize_urls_list(verdict.get("phone_numbers", []))
            id_payments = _normalize_urls_list(verdict.get("payment_identifiers", []))

            has_any_id = bool(id_urls or id_emails or id_phones or id_payments)
            if has_any_id:
                if id_urls:
                    st.write("🌐 **URLs:** " + ", ".join([f"`{u}`" for u in id_urls]))
                if id_emails:
                    st.write("✉️ **Emails:** " + ", ".join([f"`{e}`" for e in id_emails]))
                if id_phones:
                    st.write("📞 **Phone Numbers:** " + ", ".join([f"`{p}`" for p in id_phones]))
                if id_payments:
                    st.write("💳 **Payment/UPI IDs:** " + ", ".join([f"`{pid}`" for pid in id_payments]))
            else:
                st.caption("No specific URLs, emails, phone numbers, or payment identifiers detected in text.")

        # ── 3. Compact Technical Diagnostics Expander ─────────────────
        with st.expander("🔬 Technical Evidence & Individual Engine Diagnostics", expanded=False):
            st.caption(
                "Individual engine outputs are provided below for diagnostic and audit purposes. "
                "Notice: Statistical model confidence reflects training data alignment and must not be interpreted as an absolute real-world fraud probability."
            )

            e_col1, e_col2, e_col3 = st.columns(3)
            with e_col1:
                st.markdown("**Rule-Based Engine**")
                r_score = verdict.get("rule_score", 0)
                r_lvl = verdict.get("rule_level", "Low")
                st.markdown(f"Score: **{r_score}/100** · Tier: **{r_lvl}**")
            with e_col2:
                st.markdown("**TF-IDF ML Model**")
                if verdict.get("ml_prediction"):
                    st.markdown(render_ml_badge(verdict.get("ml_prediction"), verdict.get("ml_confidence")), unsafe_allow_html=True)
                else:
                    st.caption("Not available")
            with e_col3:
                st.markdown("**DistilBERT Transformer**")
                if verdict.get("hf_prediction"):
                    st.markdown(render_hf_badge(verdict.get("hf_prediction"), verdict.get("hf_confidence")), unsafe_allow_html=True)
                else:
                    st.caption("Not available")

            tab_tech_rule, tab_tech_ml, tab_tech_hf = st.tabs([
                "📐 Rule Scoring Breakdown",
                "⚡ TF-IDF ML Details",
                "🤖 DistilBERT Details",
            ])

            with tab_tech_rule:
                if verdict.get("matched_categories"):
                    st.write("**Matched Categories:**", ", ".join(verdict["matched_categories"]))
                else:
                    st.write("No rule categories matched.")

            with tab_tech_ml:
                if verdict.get("ml_prediction"):
                    st.write(f"Predicted Class: **{verdict.get('ml_prediction')}**")
                    conf = verdict.get('ml_confidence')
                    st.write(f"Decision Probability: **{conf*100:.1f}%**" if conf else "—")
                    st.write(f"Model Version: `{verdict.get('ml_model_version', 'v1.0')}`")

            with tab_tech_hf:
                if verdict.get("hf_prediction"):
                    st.write(f"Predicted Class: **{verdict.get('hf_prediction')}**")
                    hf_conf = verdict.get('hf_confidence')
                    st.write(f"Softmax Confidence: **{hf_conf*100:.1f}%**" if hf_conf else "—")
                    st.write(f"Model Version: `{verdict.get('hf_model_version', 'distilbert-v1.0')}`")

        # ── 4. Investigator Navigation ────────────────────────────────
        st.markdown('<div class="section-header">Next Steps</div>', unsafe_allow_html=True)
        nav1, nav2, _ = st.columns([1.5, 1.5, 3])
        with nav1:
            if st.button("📋 Open in Investigation Cases", key="btn_open_case", use_container_width=True):
                st.session_state["selected_case_id"] = rec_id
                st.switch_page("pages/2_Investigation_Cases.py")
        with nav2:
            if st.button("🖼️ Analyze Another Image", key="btn_new_image", use_container_width=True):
                st.session_state.ocr_extracted_text = ""
                st.session_state.ocr_confidence = None
                st.session_state.image_analyzed_record_id = None
                st.session_state.image_file_meta = None
                st.session_state.image_verdict_data = None
                st.rerun()

render_disclaimer()
