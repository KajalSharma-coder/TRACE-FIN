"""
TRACE//FIN — Analyze Advertisement Page
Dedicated investigator analysis workflow for suspicious financial advertisements (Phase 3 Dual-Engine).
Combines Phase 2 deterministic heuristic detection with Phase 3 TF-IDF + Logistic Regression ML baseline.
"""
import streamlit as st

from config import APP_NAME
from src.analysis_service import (
    run_unified_analysis,
    persist_analysis_record,
    _normalize_urls_list,
    STATUS_SUCCESS,
    STATUS_SYNTAX_ONLY,
    STATUS_EXTRACTION_FAILED,
    STATUS_EMPTY_INPUT,
    STATUS_INSUFFICIENT_CONTENT,
)
from src.database import init_db, insert_record, get_record, get_all_records, generate_record_id
from src.detector import analyze_ad, compute_unified_verdict
from src.ml_model import predict_ad_ml, compare_rule_and_ml, get_model_metrics
from src.hf_model import predict_ad_hf, get_hf_model_info
from src.url_fetcher import analyze_url
from src.browser_analysis import analyze_browser_url
from src.document_extractor import extract_pdf_text, extract_docx_text
from src.ocr_engine import validate_image, extract_text_ocr, is_tesseract_available
from src.evidence_graph import build_evidence_graph, make_3d_figure
from src.sample_data import seed_demo_data
from src.ui_components import (
    inject_global_css, render_sidebar, render_demo_banner,
    render_record_detail, render_disclaimer, render_ml_badge,
    render_hf_badge, render_consensus_card, render_risk_badge,
    render_status_badge,
)

# ── Page Config ────────────────────────────────────────────────────────
st.set_page_config(
    page_title=f"{APP_NAME} — Multi-Format Analysis",
    page_icon="🔍",
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
st.markdown("# 🔍 Unified Multi-Format Advertisement Analysis")
st.caption("Investigative Intake for Raw Text, Website URLs, Posters/Images, PDF Briefs, & Word Documents")
render_demo_banner()

# ── Session state ──────────────────────────────────────────────────────
if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None
if "analysis_graph_data" not in st.session_state:
    st.session_state.analysis_graph_data = None
if "analysis_related_records" not in st.session_state:
    st.session_state.analysis_related_records = []
if "ml_result" not in st.session_state:
    st.session_state.ml_result = None
if "hf_result" not in st.session_state:
    st.session_state.hf_result = None
if "verdict_data" not in st.session_state:
    st.session_state.verdict_data = None
if "saved_record_id" not in st.session_state:
    st.session_state.saved_record_id = None
if "current_review_text" not in st.session_state:
    st.session_state.current_review_text = ""
if "reviewed_ad_text" not in st.session_state:
    st.session_state.reviewed_ad_text = ""
if "source_meta" not in st.session_state:
    st.session_state.source_meta = {
        "type": "Direct Text",
        "details": "Manual text input",
        "warnings": [],
        "indicators": [],
    }

def reset_all_state() -> None:
    """Reset review text, widget state, source metadata, and prior results cleanly."""
    st.session_state.reviewed_ad_text = ""
    st.session_state.current_review_text = ""
    st.session_state.analysis_result = None
    st.session_state.analysis_graph_data = None
    st.session_state.analysis_related_records = []
    st.session_state.ml_result = None
    st.session_state.hf_result = None
    st.session_state.verdict_data = None
    st.session_state.saved_record_id = None
    st.session_state.source_meta = {
        "type": "Direct Text",
        "details": "Manual text input",
        "warnings": [],
        "indicators": [],
    }

# Check for pending reset flag before any widgets are instantiated in the current run
if st.session_state.get("_reset_pending"):
    reset_all_state()
    st.session_state._reset_pending = False

def update_review_state(
    text: str,
    source_type: str,
    details: str,
    warnings: list = None,
    indicators: list = None,
    extra_meta: dict = None,
) -> None:
    """
    Single canonical state synchronization mechanism for all 5 intake handlers.
    Sets both current_review_text and the widget state key reviewed_ad_text
    before widget instantiation in strict compliance with Streamlit lifecycle rules.
    """
    clean_text = (text or "").strip()
    st.session_state.current_review_text = clean_text
    st.session_state.reviewed_ad_text = clean_text
    meta = {
        "type": source_type,
        "details": details,
        "warnings": list(warnings or []),
        "indicators": list(indicators or []),
    }
    if extra_meta:
        meta.update(extra_meta)
    st.session_state.source_meta = meta

# ── Step 1: Multi-Format Intake ───────────────────────────────────────
st.markdown('<div class="section-header">1. Select Input Source & Extract Content</div>',
            unsafe_allow_html=True)

tab_raw, tab_url, tab_img, tab_pdf, tab_docx = st.tabs([
    "📝 Raw Text",
    "🌐 Website URL",
    "🖼️ Screenshot / Image",
    "📄 PDF Document",
    "📑 Word Document (DOCX)",
])

with tab_raw:
    st.caption("Paste advertisement text, chat transcripts, or message bodies directly.")
    example_prompts = [
        "Select an example or paste custom text below…",
        "Selling fully KYC verified HDFC account. Contact Telegram @seller. Call 9876543210",
        "Rent your bank account for 10k/month. Send details to Pooja Jain. Acc: 61641030277, IFSC: ICIC0475599",
        "Bank accounts for sale, no KYC required! Guaranteed instant access. Telegram @seller",
        "Work from home: receive transfers into your personal account and keep 10% commission",
        "Vendor payment details: Rohan Kumar, Bank: HDFC, Acc: 66562328946, IFSC: HDFC0437589",
    ]
    selected_example = st.selectbox("Quick Load Realistic Examples:", example_prompts, index=0)

    raw_input_text = st.text_area(
        "Direct Advertisement Content",
        value=selected_example if selected_example != example_prompts[0] else "",
        height=140,
        placeholder="Enter text to analyze…",
        key="raw_text_intake",
    )
    if st.button("📥 Load into Review Area", key="btn_load_raw"):
        if raw_input_text.strip():
            update_review_state(
                text=raw_input_text,
                source_type="Direct Text",
                details=f"{len(raw_input_text.split())} words entered manually",
                warnings=[],
                indicators=[],
            )
            st.success("✓ Text loaded into verification review area below.")
            st.rerun()
        else:
            st.warning("Please enter or select text first.")

with tab_url:
    st.caption("Safely analyze suspicious financial websites with strict SSRF defense (private IPs & cloud metadata blocked).")
    input_url = st.text_input(
        "Website URL to Analyze",
        placeholder="https://example-financial-offer.com/account-sales",
        key="input_url_field",
    )
    col_u1, col_u2 = st.columns([1, 1])
    with col_u1:
        fetch_live = st.checkbox("Retrieve live website content (5s timeout, 2MB cap)", value=True, key="chk_fetch_live")
    with col_u2:
        btn_inspect_url = st.button("🌐 Safely Fetch & Inspect URL", key="btn_inspect_url", type="primary")

    with st.expander("Optional offline browser analysis"):
        st.caption("Fetches through TRACE//FIN's SSRF protections, then renders escaped extracted text locally with page scripts and network requests disabled.")
        run_browser_analysis = st.button("🧭 Analyze with offline browser", key="btn_browser_url")

    if run_browser_analysis:
        if not input_url or not input_url.strip():
            st.error("Please enter a valid HTTP/HTTPS URL.")
        else:
            with st.spinner("Safely fetching and analyzing the page…"):
                browser_result = analyze_browser_url(input_url.strip())
            st.markdown("**Browser analysis**")
            st.write(f"URL: `{browser_result['url']}`")
            st.write(f"Final URL: `{browser_result['final_url']}` · Redirects: {browser_result['redirects']}")
            st.write(f"Page title: {browser_result['title'] or '(no title)'}")
            if browser_result.get("fetch_error"):
                st.warning(f"Page fetch unavailable: {browser_result['fetch_error']}")
            if browser_result.get("browser_error"):
                st.caption(browser_result["browser_error"])
            url_model = browser_result.get("url_model", {})
            if url_model.get("available"):
                st.write(f"**Phishing URL model:** {url_model['prediction']} ({url_model['phishing_probability']:.1%})")
            elif url_model.get("error"):
                st.caption(f"Phishing URL model unavailable: {url_model['error']}")
            ad = browser_result["advertisement_analysis"]
            st.write(f"**Financial advertisement assessment:** {ad.get('final_verdict', 'UNSCORED')} · score {ad.get('final_score') if ad.get('final_score') is not None else 'unavailable'}")
            st.caption("URL phishing classification and financial advertisement assessment are separate signals.")
            if ad.get("evidence"):
                st.markdown("**Advertisement evidence**")
                for item in ad["evidence"]:
                    st.write(f"• {item}")
            if browser_result.get("visible_text"):
                with st.expander("Extracted visible webpage text"):
                    st.text(browser_result["visible_text"][:20_000])

    if btn_inspect_url:
        if not input_url or not input_url.strip():
            st.error("Please enter a valid HTTP/HTTPS URL.")
        else:
            with st.spinner("Executing safe DNS resolution and SSRF-protected retrieval…"):
                url_res = analyze_url(input_url.strip(), fetch_content=fetch_live)

            if not url_res["valid"]:
                st.error(f"❌ URL Validation Error: {url_res['error']}")
            else:
                st.info(f"ℹ️ **Disclosure:** {url_res['disclosure']}")
                url_model = url_res.get("url_model") or {}
                if url_model.get("available"):
                    st.caption(
                        f"Supplementary URL model: **{url_model.get('prediction')}** · "
                        f"{url_model.get('phishing_probability', 0):.1%} phishing likelihood. "
                        "This generic phishing signal does not change the financial-ad risk score."
                    )
                elif url_model.get("error"):
                    st.caption(f"Supplementary URL model unavailable: {url_model['error']}")
                if url_res.get("indicators"):
                    for ind in url_res["indicators"]:
                        st.warning(f"⚠️ {ind}")

                if url_res.get("extracted_text"):
                    update_review_state(
                        text=url_res["extracted_text"],
                        source_type="Website URL",
                        details=f"URL: {url_res['hostname']} ({url_res.get('status_code', 'N/A')})",
                        warnings=url_res.get("warnings", []),
                        indicators=url_res.get("indicators", []),
                        extra_meta={"final_url": url_res.get("final_url", input_url.strip()),
                                    "url_model_results": [url_model] if url_model else []},
                    )
                    st.success(f"✓ Extracted {len(url_res['extracted_text'].split()):,} words from page '{url_res.get('title', 'Untitled')}'. Loaded into Review Area.")
                    st.rerun()
                else:
                    # Syntax-only mode or live fetch without text / fetch failure
                    warn_list = list(url_res.get("warnings", []))
                    failure_category = url_res.get("failure_category")
                    network_failure = failure_category in {
                        "dns_resolution_failed", "connection_failed", "connection_timeout", "tls_error"
                    }
                    if url_res.get("error") and not network_failure:
                        warn_list.append(url_res.get("error"))
                    syntax_text = f"URL domain analysis: {url_res['hostname']}"
                    if url_res.get("indicators"):
                        syntax_text += "\nIndicators: " + "; ".join(url_res["indicators"])

                    if not fetch_live:
                        src_type = "Website URL (Syntax Only)"
                        detail_msg = f"Hostname: {url_res['hostname']} (Syntax Only)"
                    else:
                        src_type = "Website URL (Fetch Failed)"
                        if network_failure:
                            detail_msg = f"Network fetch failed ({failure_category}): {url_res.get('error', 'No page content retrieved')}"
                        else:
                            detail_msg = f"Fetch failed: {url_res.get('error', 'No text extracted')}"

                    fetch_notice = None
                    if network_failure:
                        fetch_notice = (
                            "The page could not be fetched because DNS/network access failed. "
                            "This is not evidence that the URL is suspicious; page risk is unscored until content is available."
                        )

                    update_review_state(
                        text=syntax_text,
                        source_type=src_type,
                        details=detail_msg,
                        warnings=warn_list,
                        indicators=url_res.get("indicators", []),
                        extra_meta={"final_url": url_res.get("final_url", input_url.strip()),
                                    "url_model_results": [url_model] if url_model else [],
                                    "fetch_failure_category": failure_category,
                                    "fetch_error": url_res.get("error"),
                                    "fetch_notice": fetch_notice},
                    )
                    if fetch_notice:
                        st.info(fetch_notice)
                    st.info(f"Loaded {src_type} into Review Area for triage.")
                    st.rerun()

with tab_img:
    st.caption("Upload advertisement posters, chat screenshots, or social media graphics (JPG, PNG, WEBP).")
    img_file = st.file_uploader("Upload Image or Screenshot", type=["jpg", "jpeg", "png", "webp"], key="unified_img_uploader")
    if img_file is not None:
        val_img = validate_image(img_file)
        if not val_img["valid"]:
            st.error(f"❌ Image Error: {val_img['error']}")
        else:
            c_prev, c_ocr = st.columns([1, 1])
            with c_prev:
                st.image(val_img["image"], caption=f"{img_file.name} ({val_img['dimensions'][0]}×{val_img['dimensions'][1]} px)", use_container_width=True)
            with c_ocr:
                st.write(f"File size: **{val_img['file_size_kb']:.1f} KB**")
                if st.button("⚡ Run Local OCR (EasyOCR / Tesseract)", key="btn_ocr_unified"):
                    with st.spinner("Extracting text locally via EasyOCR / Tesseract fallback…"):
                        ocr_out = extract_text_ocr(val_img["image"])
                    if ocr_out["available"] and ocr_out["text"].strip():
                        warn_list = [ocr_out["error"]] if ocr_out.get("error") else []
                        update_review_state(
                            text=ocr_out["text"],
                            source_type="Image OCR",
                            details=f"File: {img_file.name} (OCR Conf: {ocr_out.get('confidence', 0):.1f}%)",
                            warnings=warn_list,
                            indicators=[],
                        )
                        st.success(f"✓ Extracted {len(ocr_out['text'].split())} words. Loaded into Review Area.")
                        st.rerun()
                    else:
                        st.error(f"OCR Error: {ocr_out.get('error', 'No readable text detected in image.')}")

with tab_pdf:
    st.caption("Extract text from PDF flyers, campaign dossiers, or transaction receipts (max 30 pages, 10MB).")
    pdf_file = st.file_uploader("Upload PDF Document", type=["pdf"], key="unified_pdf_uploader")
    if pdf_file is not None:
        if st.button("📄 Extract PDF Text", key="btn_extract_pdf"):
            with st.spinner("Extracting text page-by-page…"):
                pdf_out = extract_pdf_text(pdf_file)
            if not pdf_out["valid"] or pdf_out.get("error"):
                st.error(f"❌ PDF Error: {pdf_out['error']}")
            else:
                meta = pdf_out.get("metadata", {})
                update_review_state(
                    text=pdf_out["text"],
                    source_type="PDF Document",
                    details=f"File: {pdf_file.name} ({meta.get('total_pages', 0)} pages, {meta.get('size_kb', 0)} KB)",
                    warnings=pdf_out.get("warnings", []),
                    indicators=[],
                )
                if pdf_out.get("warnings"):
                    for w in pdf_out["warnings"]:
                        st.warning(f"⚠️ {w}")
                st.success(f"✓ Extracted {len(pdf_out['text'].split()):,} words from PDF. Loaded into Review Area.")
                st.rerun()

with tab_docx:
    st.caption("Extract text from Word document memos, transcripts, or reports (.docx).")
    docx_file = st.file_uploader("Upload Word Document", type=["docx"], key="unified_docx_uploader")
    if docx_file is not None:
        if st.button("📑 Extract DOCX Content", key="btn_extract_docx"):
            with st.spinner("Extracting paragraphs and tables…"):
                docx_out = extract_docx_text(docx_file)
            if not docx_out["valid"] or docx_out.get("error"):
                st.error(f"❌ DOCX Error: {docx_out['error']}")
            else:
                meta = docx_out.get("metadata", {})
                update_review_state(
                    text=docx_out["text"],
                    source_type="DOCX Document",
                    details=f"File: {docx_file.name} ({meta.get('paragraphs_extracted', 0)} paragraphs, {meta.get('table_rows_extracted', 0)} table rows)",
                    warnings=docx_out.get("warnings", []),
                    indicators=[],
                )
                if docx_out.get("warnings"):
                    for w in docx_out["warnings"]:
                        st.warning(f"⚠️ {w}")
                st.success(f"✓ Extracted {len(docx_out['text'].split()):,} words from Word document. Loaded into Review Area.")
                st.rerun()

# ── Step 2: Investigator Review & Content Verification (Editable) ───────
st.markdown('<div class="section-header">2. Investigator Review & Verification (Editable)</div>',
            unsafe_allow_html=True)
st.caption("Review, edit, or sanitize extracted content before authorizing threat intelligence detection.")

source_info = st.session_state.source_meta
badge_col = "#38bdf8"
st.markdown(
    f"""
    <div style="background: rgba(30, 41, 59, 0.6); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 6px; padding: 0.6rem 0.9rem; margin-bottom: 0.8rem; font-size: 0.85rem;">
        <strong>Active Ingestion Source:</strong> <span style="color: {badge_col}; font-weight: 600;">{source_info.get('type', 'Direct Text')}</span> · {source_info.get('details', '')}
    </div>
    """,
    unsafe_allow_html=True,
)

if source_info.get("warnings"):
    for warn in source_info["warnings"]:
        st.warning(f"⚠️ **Extraction Warning:** {warn}")
if source_info.get("fetch_notice"):
    st.info(source_info["fetch_notice"])

ad_text = st.text_area(
    "Verified Content for Threat Analysis",
    height=160,
    placeholder="Extracted or loaded content will appear here for investigator review and editing before running triage…",
    key="reviewed_ad_text",
)

# Synchronize current_review_text with latest user edits from the widget
st.session_state.current_review_text = ad_text

char_count = len(ad_text) if ad_text else 0
word_count = len(ad_text.split()) if ad_text else 0
st.caption(f"Review metrics: **{char_count:,}** characters · **{word_count:,}** words")

# Action buttons
btn_col1, btn_col2, _ = st.columns([1.5, 1, 3])

with btn_col1:
    analyze_clicked = st.button(
        "🔍 Analyze Reviewed Content",
        type="primary",
        use_container_width=True,
        key="btn_analyze_reviewed",
    )

with btn_col2:
    clear_clicked = st.button(
        "✕ Reset All",
        use_container_width=True,
        on_click=reset_all_state,
        key="btn_reset_all",
    )

# ── Handle Clear (Fallback safety if triggered without on_click) ───────
if clear_clicked:
    st.session_state._reset_pending = True
    st.rerun()

# ── Handle Analysis ───────────────────────────────────────────────────
if analyze_clicked:
    # Always read the latest reviewed text from widget state
    latest_review_text = (st.session_state.get("reviewed_ad_text") or ad_text or "").strip()
    if not latest_review_text:
        st.error("⚠ Validation Error: Reviewed text is empty. Select an intake format and load content before running analysis.")
    else:
        src_type = source_info.get("type", "Direct Text")
        if "Syntax Only" in src_type:
            ext_status = STATUS_SYNTAX_ONLY
            ext_err = "Domain syntax only; live webpage content was not fetched."
        elif "Fetch Failed" in src_type:
            ext_status = STATUS_EXTRACTION_FAILED
            ext_err = source_info.get("details", "Webpage content retrieval failed.")
        else:
            ext_status = STATUS_SUCCESS
            ext_err = None

        with st.spinner("Executing multi-engine threat detection (Rules + TF-IDF ML + DistilBERT)…"):
            unified_res = run_unified_analysis(
                text=latest_review_text,
                source_type=src_type,
                source_metadata=source_info,
                extraction_status=ext_status,
                extraction_error=ext_err,
            )

        # Save to database with multi-engine attributes via canonical persistence service
        saved_id = persist_analysis_record(unified_res)
        try:
            st.session_state.analysis_related_records = get_all_records()
        except Exception:
            st.session_state.analysis_related_records = []

        st.session_state.analysis_result = {
            "risk_score": unified_res["rule_score"],
            "risk_level": unified_res["rule_level"],
            "matched_rules": unified_res.get("matched_rules", []),
            "matched_categories": unified_res.get("matched_categories", []),
            "evidence": unified_res.get("evidence", []),
            "urls": unified_res.get("urls", []),
            "emails": unified_res.get("emails", []),
            "phone_numbers": unified_res.get("phone_numbers", []),
            "payment_identifiers": unified_res.get("payment_identifiers", []),
        }
        st.session_state.analysis_graph_data = {**unified_res, "record_id": saved_id}
        st.session_state.ml_result = {
            "available": unified_res.get("engine_status", {}).get("tfidf") == "available",
            "error": unified_res.get("engine_errors", {}).get("tfidf"),
            "risk_label": unified_res.get("ml_prediction"),
            "confidence": unified_res.get("ml_confidence"),
            "high_risk_score": unified_res.get("ml_decision_score"),
            "model_version": unified_res.get("ml_model_version"),
            "top_signals": unified_res.get("ml_top_signals", []),
        }
        st.session_state.hf_result = {
            "available": unified_res.get("engine_status", {}).get("distilbert") == "available",
            "error": unified_res.get("engine_errors", {}).get("distilbert"),
            "risk_label": unified_res.get("hf_prediction"),
            "confidence": unified_res.get("hf_confidence"),
            "class_probabilities": unified_res.get("hf_class_probabilities"),
            "high_risk_score": unified_res.get("hf_decision_score"),
            "model_version": unified_res.get("hf_model_version"),
        }
        st.session_state.verdict_data = {
            "final_verdict": unified_res["final_verdict"],
            "final_score": unified_res["final_score"],
            "explanation": unified_res["explanation"],
            "recommendation": unified_res["recommendation"],
            "investigation_status": unified_res["investigation_status"],
            "review_required": unified_res["review_required"],
            "has_sufficient_evidence": unified_res["has_sufficient_evidence"],
            "consensus_status": unified_res.get("consensus_status", "Evaluated"),
        }
        st.session_state.saved_record_id = saved_id
        st.success(f"✓ Analysis complete. Case registered as **{saved_id}** with status **{unified_res['investigation_status']}**.")

# ── Step 3: Display Results ───────────────────────────────────────────
if st.session_state.analysis_result and st.session_state.saved_record_id:
    record_id = st.session_state.saved_record_id
    saved_record = get_record(record_id)

    if saved_record:
        rule_res = st.session_state.analysis_result or {}
        ml_res = st.session_state.ml_result or {}
        hf_res = st.session_state.hf_result or {}
        verdict = st.session_state.get("verdict_data")
        if not verdict:
            verdict = compute_unified_verdict(rule_res, ml_res, hf_res)

        final_verdict = verdict["final_verdict"]  # "HIGH RISK", "MEDIUM RISK", "LOW RISK", "INSUFFICIENT EVIDENCE"
        final_score = verdict.get("final_score")
        explanation = verdict["explanation"]
        recommendation = verdict["recommendation"]
        status = verdict["investigation_status"]

        # Color palette for verdict
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
        else:  # LOW RISK
            v_color = "#22c55e"
            v_bg = "rgba(34, 197, 94, 0.12)"
            v_border = "rgba(34, 197, 94, 0.5)"
            v_icon = "🛡️"

        score_display = (
            f"{int(final_score)} <span style=\"font-size: 1.1rem; color: #94a3b8; font-weight: 500;\">/ 100</span>"
            if final_score is not None
            else "<span style=\"font-size: 1.6rem; color: #94a3b8;\">N/A</span>"
        )

        st.markdown("---")
        st.markdown('<div class="section-header">3. Threat Analysis Dossier & Unified Verdict</div>',
                    unsafe_allow_html=True)

        graph_data = build_evidence_graph(
            st.session_state.get("analysis_graph_data") or rule_res,
            text=st.session_state.get("reviewed_ad_text", ""),
            source_type=source_info.get("type", "Advertisement text"),
            source_meta=source_info,
            related_records=st.session_state.get("analysis_related_records", []),
        )
        graph_nodes = graph_data["nodes"]
        category_options = sorted({node["type"] for node in graph_nodes})
        control_col, risk_col = st.columns([1.7, 1])
        with control_col:
            selected_categories = st.multiselect(
                "Evidence categories", category_options, default=category_options,
                key=f"graph_categories_{record_id}",
            )
        with risk_col:
            high_risk_only = st.toggle("High-risk evidence only", key=f"graph_high_only_{record_id}")
        visible_nodes = [node for node in graph_nodes
                         if node["type"] in selected_categories
                         and (not high_risk_only or node["risk"] == "high")]
        if graph_data["central_id"] not in {node["id"] for node in visible_nodes}:
            visible_nodes.insert(0, next(node for node in graph_nodes if node["id"] == graph_data["central_id"]))
        visible_ids = {node["id"] for node in visible_nodes}
        visible_edges = [edge for edge in graph_data["edges"]
                         if edge["source"] in visible_ids and edge["target"] in visible_ids]
        visible_graph = {**graph_data, "nodes": visible_nodes, "edges": visible_edges}

        evidence_col, summary_col = st.columns([2.15, 1])
        with evidence_col:
            st.markdown("#### Interactive 3D evidence graph")
            st.caption("Drag to rotate · scroll to zoom · right-drag to pan · select a node for its evidence details.")
            selected_point_ids = set()
            prior_selection = st.session_state.get(f"graph_selection_{record_id}")
            if prior_selection:
                selected_point_ids.add(prior_selection)
                selected_node = next((n for n in graph_nodes if n["id"] == prior_selection), None)
                if selected_node:
                    selected_point_ids.update(selected_node["related_ids"])
            figure = make_3d_figure(visible_graph, selected_point_ids)
            try:
                from streamlit_plotly_events import plotly_events
                clicked = plotly_events(
                    figure, click_event=True, select_event=False, hover_event=False,
                    override_height=610, key=f"evidence_graph_{record_id}",
                )
            except ImportError:
                st.plotly_chart(figure, key=f"evidence_graph_{record_id}",
                                config={"displaylogo": False, "scrollZoom": True,
                                        "modeBarButtonsToAdd": ["resetCameraDefault3d"]})
                st.caption("Node click details are available after installing streamlit-plotly-events.")
                clicked = []
            if clicked:
                point = clicked[-1]
                node_trace = len(figure.data) - 1
                point_index = point.get("pointIndex", point.get("pointNumber"))
                selected_id = None
                if point.get("curveNumber") == node_trace and isinstance(point_index, int):
                    if 0 <= point_index < len(visible_nodes):
                        selected_id = visible_nodes[point_index]["id"]
                if selected_id in visible_ids and selected_id != st.session_state.get(f"graph_selection_{record_id}"):
                    st.session_state[f"graph_selection_{record_id}"] = selected_id
                    st.rerun()
            st.caption("Legend: cyan = advertisement · blue = URL/domain · purple = verification · amber = contact/payment · red = high-risk evidence · green = rule match.")
        with summary_col:
            st.markdown("#### Risk assessment")
            st.metric("Advertisement classification", graph_data["classification"])
            if graph_data["risk_score"] is not None:
                st.metric("Overall risk score", f"{graph_data['risk_score']}/100")
            else:
                st.metric("Overall risk score", "Unavailable")
            st.write(f"Evidence nodes: **{graph_data['evidence_count']}** · High-risk: **{graph_data['high_risk_count']}**")
            url_results = graph_data.get("url_models") or []
            if url_results:
                st.markdown("**URL phishing model**")
                for item in url_results:
                    prediction = item.get("prediction") or ("Unavailable" if not item.get("available") else "No result")
                    st.write(f"{prediction}" + (f" — {item.get('error')}" if item.get("error") else ""))
            else:
                st.caption("URL phishing model: no URL model result for this analysis.")
            st.markdown(f"**Advertisement text analysis:** {classification if (classification := graph_data['classification']) else 'Unavailable'}")
            if source_info.get("type") == "Image OCR":
                st.caption("Image: OCR text was analyzed. Fake-logo and visual authenticity checks are unavailable.")
            picked_id = st.session_state.get(f"graph_selection_{record_id}")
            picked_node = next((node for node in graph_nodes if node["id"] == picked_id), None)
            if picked_node:
                st.markdown("---")
                st.markdown(f"**{picked_node['label']}**")
                st.write(picked_node["value"])
                st.caption(f"Source: {picked_node['source']} · Risk: {picked_node['risk'].title()}")
                st.caption(picked_node["reason"])
                if picked_node.get("confidence") is not None:
                    st.caption(f"Model score: {picked_node['confidence']:.1%} (not a calibrated fraud probability)")

        with st.expander("Evidence list", expanded=False):
            for node in visible_nodes:
                st.markdown(f"**{node['label']}** · `{node['risk']}`  \n{node['value']}  \nSource: {node['source']} · {node['reason']}")

        st.markdown("---")

        # ── 1. One Prominent Final Risk Result Card ───────────────────────
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
                        <strong>Case Status:</strong> <span style="font-weight: 600;">{status}</span> · Record ID: <code>{record_id}</code>
                    </div>
                </div>
                <div style="margin-top: 0.8rem; font-size: 0.78rem; color: #94a3b8; font-style: italic;">
                    ⚖️ Decision-support triage verdict. Statistical models and rule heuristics do not definitively prove criminal fraud; all flagged cases require authorized investigator verification.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # ── 2. Key Evidence & Extracted Identifiers Panel ───────────────────
        st.markdown('<div class="section-header">Key Evidence & Extracted Identifiers</div>', unsafe_allow_html=True)
        ev_col, id_col = st.columns([1.2, 1])

        with ev_col:
            st.markdown("**Rule Engine Evidence Matches**")
            for item in rule_res.get("evidence", []):
                if "[Model Availability]" in str(item):
                    st.warning(str(item))
            matched_rules = rule_res.get("matched_rules", [])
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
            id_urls = _normalize_urls_list(rule_res.get("urls", []))
            id_emails = _normalize_urls_list(rule_res.get("emails", []))
            id_phones = _normalize_urls_list(rule_res.get("phone_numbers", []))
            id_payments = _normalize_urls_list(rule_res.get("payment_identifiers", []))

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

        # ── 3. Technical Evidence & Individual Engine Diagnostics ──────────
        with st.expander("🔬 Technical Evidence & Individual Engine Diagnostics", expanded=False):
            st.caption(
                "Individual engine outputs are provided below for diagnostic and audit purposes. "
                "Notice: Statistical model confidence reflects training data alignment and must not be interpreted as an absolute real-world fraud probability."
            )

            eng_c1, eng_c2, eng_c3 = st.columns(3)
            with eng_c1:
                st.markdown("**Rule-Based Engine**")
                r_score = rule_res.get("risk_score", 0)
                r_lvl = rule_res.get("risk_level", "Low")
                st.markdown(f"Score: **{r_score}/100** · Tier: **{r_lvl}**")
            with eng_c2:
                st.markdown("**TF-IDF ML Model**")
                if ml_res.get("available"):
                    st.markdown(render_ml_badge(ml_res.get("risk_label"), ml_res.get("confidence")), unsafe_allow_html=True)
                else:
                    st.caption("Not available")
            with eng_c3:
                st.markdown("**DistilBERT Transformer**")
                if hf_res.get("available"):
                    st.markdown(render_hf_badge(hf_res.get("risk_label"), hf_res.get("confidence")), unsafe_allow_html=True)
                else:
                    st.caption("Not available")

            tab_tech_rule, tab_tech_ml, tab_tech_hf = st.tabs([
                "📐 Rule Scoring Breakdown",
                "⚡ TF-IDF ML Details",
                "🤖 DistilBERT Details",
            ])

            with tab_tech_rule:
                st.markdown("**Configured Rule Categories & Weights:**")
                st.markdown(
                    "- **Category A (Account & Payment Instrument Sale):** +35 pts\n"
                    "- **Category B (KYC Evasion & Identity Circumvention):** +30 pts\n"
                    "- **Category C (Mule Account Rental & Liquidation):** +35 pts\n"
                    "- **Category D (Suspicious Financial Solicitation / Hawala):** +20 pts\n"
                    "- **Category E (High-Pressure Urgency & Secrecy):** +10 pts\n"
                    "- **Legitimate Advisory Mitigation:** -35 to -45 pts\n"
                    "- **Identified Contact Multipliers:** +5 to +10 pts (capped 0–100)"
                )
                if rule_res.get("matched_categories"):
                    st.write("**Matched Categories:**", ", ".join(rule_res["matched_categories"]))
                else:
                    st.write("No rule categories matched.")
                for matched in rule_res.get("matched_rules", []):
                    st.write(
                        f"• {matched.get('rule_name', 'Rule')} "
                        f"(+{matched.get('weight', 0)}): {matched.get('evidence', '')}"
                    )
                st.write("**Final synthesis branch:**", verdict.get("consensus_status", "Evaluated"))

            with tab_tech_ml:
                if ml_res.get("available"):
                    m1, m2 = st.columns(2)
                    with m1:
                        st.write(f"Model Version: `{ml_res.get('model_version', 'v1.0')}`")
                        st.write(f"Predicted Class: **{ml_res.get('risk_label')}**")
                        conf_pct = ml_res.get('confidence', 0) * 100
                        st.write(f"Decision Probability: **{conf_pct:.1f}%**")
                    with m2:
                        st.write("Architecture: Sublinear TF-IDF (1,2-grams) + Logistic Regression")
                        st.write("Training Class Distribution: 50% High Risk / 50% Safe")

                    signals = ml_res.get("top_signals", [])
                    if signals:
                        st.markdown("**Top Token Influences:**")
                        sig_cols = st.columns(min(len(signals), 4))
                        for idx, sig in enumerate(signals[:4]):
                            with sig_cols[idx]:
                                dir_color = "#f97316" if sig["direction"] == "High Risk" else "#22c55e"
                                st.markdown(
                                    f"<div style='background: rgba(30,41,59,0.7); padding: 0.4rem; border-radius: 4px; font-size: 0.8rem;'>"
                                    f"<code>{sig['token']}</code><br><span style='color: {dir_color};'>{sig['direction']} ({sig['weight']:+.3f})</span>"
                                    f"</div>",
                                    unsafe_allow_html=True,
                                )
                    st.caption(f"Interpretability Note: {ml_res.get('disclaimer', '')}")

                    metrics = get_model_metrics()
                    if metrics:
                        with st.expander("📊 View Model Training Metrics & Evaluation"):
                            st.json(metrics)
                else:
                    st.warning(f"ML model not available: {ml_res.get('error') or 'no model output was returned'}")

            with tab_tech_hf:
                if hf_res.get("available"):
                    hf_info = get_hf_model_info() or {}
                    h1, h2 = st.columns(2)
                    with h1:
                        st.write(f"Model: `{hf_res.get('model_version', 'distilbert')}`")
                        st.write(f"Predicted Class: **{hf_res.get('risk_label')}**")
                        hf_conf_pct = hf_res.get('confidence', 0) * 100
                        st.write(f"Predicted-class confidence: **{hf_conf_pct:.1f}%**")
                        probabilities = hf_res.get("class_probabilities") or {}
                        if probabilities:
                            st.write(
                                "Class probabilities: "
                                f"Safe **{probabilities.get('Safe', 0) * 100:.1f}%** · "
                                f"High Risk **{probabilities.get('High Risk', 0) * 100:.1f}%**"
                            )
                    with h2:
                        st.write(f"Base: {hf_info.get('base_model', 'unknown')}")
                        st.write(f"Fine-tuning task: {hf_info.get('task_definition', 'unverified for this legacy artifact')}")
                    st.caption(f"Interpretability Note: {hf_res.get('disclaimer', '')}")
                    if hf_info:
                        with st.expander("📊 View DistilBERT Fine-Tuning Metadata & Evaluation"):
                            st.json(hf_info)
                else:
                    hf_error = hf_res.get("error") or "no model output was returned"
                    st.warning(f"DistilBERT model unavailable or skipped: {hf_error}")

        # ── 4. Investigator Navigation ────────────────────────────────────
        st.markdown('<div class="section-header">Next Steps</div>', unsafe_allow_html=True)
        nav_col1, nav_col2, _ = st.columns([1.5, 1.2, 2.5])
        with nav_col1:
            if st.button("📋 Open in Investigation Cases", use_container_width=True):
                st.session_state["selected_case_id"] = record_id
                st.switch_page("pages/2_Investigation_Cases.py")
        with nav_col2:
            if st.button("🔍 Analyze Another Ad", use_container_width=True):
                st.session_state.analysis_result = None
                st.session_state.analysis_graph_data = None
                st.session_state.analysis_related_records = []
                st.session_state.ml_result = None
                st.session_state.hf_result = None
                st.session_state.verdict_data = None
                st.session_state.saved_record_id = None
                st.rerun()
    else:
        st.error(f"Error: Record {record_id} could not be retrieved from the database.")

# ── Empty state guidance ──────────────────────────────────────────────
if not st.session_state.analysis_result:
    st.markdown("---")
    st.info("No completed advertisement analysis yet. Submit reviewed text above to generate its evidence graph and risk summary.")
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
