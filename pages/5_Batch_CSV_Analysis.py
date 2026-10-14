"""
TRACE//FIN — CSV Batch Analysis Page (Phase 4)
Upload batches of advertisement text records via CSV, configure column mapping,
run rule-based heuristics and ML classifiers, preview high-risk alerts,
and download sanitized CSV exports protected against spreadsheet formula injection.
"""

import streamlit as st
import pandas as pd

from config import APP_NAME
from src.csv_analyzer import validate_csv, run_batch_analysis, export_safe_csv, MAX_ROWS, MAX_SIZE_MB
from src.database import init_db
from src.sample_data import seed_demo_data
from src.ui_components import (
    inject_global_css, render_sidebar, render_demo_banner,
    render_disclaimer, render_risk_badge, render_ml_badge,
)

# ── Page Config ────────────────────────────────────────────────────────
st.set_page_config(
    page_title=f"{APP_NAME} — Batch CSV Analysis",
    page_icon="📑",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()
seed_demo_data()
inject_global_css()
render_sidebar()

# ── Header ─────────────────────────────────────────────────────────────
st.markdown("# 📑 Batch CSV Advertisement Analysis")
st.caption("Bulk Triage Engine for Law Enforcement & Financial Intelligence Units")
render_demo_banner()

# ── Session State ──────────────────────────────────────────────────────
if "batch_raw_df" not in st.session_state:
    st.session_state.batch_raw_df = None
if "batch_results_df" not in st.session_state:
    st.session_state.batch_results_df = None
if "batch_filename" not in st.session_state:
    st.session_state.batch_filename = ""

# ── Step 1: Upload CSV File ────────────────────────────────────────────
st.markdown('<div class="section-header">1. Upload Batch Dataset (CSV)</div>', unsafe_allow_html=True)
st.caption(f"Constraints: Maximum **{MAX_ROWS:,}** rows · Maximum file size: **{MAX_SIZE_MB} MB** · Auto-detects UTF-8, Latin-1, CP1252")

uploaded_csv = st.file_uploader(
    "Choose a CSV file containing advertisement texts",
    type=["csv"],
    key="batch_csv_uploader",
    help="Files are processed in memory and never retained on disk.",
)

if uploaded_csv is not None and uploaded_csv.name != st.session_state.batch_filename:
    val_res = validate_csv(uploaded_csv)
    if not val_res["valid"]:
        st.error(f"❌ CSV Validation Error: {val_res['error']}")
        st.session_state.batch_raw_df = None
        st.session_state.batch_results_df = None
        st.session_state.batch_filename = ""
    else:
        st.session_state.batch_raw_df = val_res["df"]
        st.session_state.batch_filename = uploaded_csv.name
        st.session_state.batch_results_df = None
        st.success(f"✓ Successfully loaded **{uploaded_csv.name}** ({val_res['row_count']:,} rows, {len(val_res['columns'])} columns).")

raw_df = st.session_state.batch_raw_df

if raw_df is not None:
    # Preview raw table
    with st.expander("👁️ Preview Raw CSV Data (First 5 Rows)", expanded=False):
        st.dataframe(raw_df.head(5), use_container_width=True)

    # ── Step 2: Column Selection ───────────────────────────────────────
    st.markdown('<div class="section-header">2. Configure Column Mapping</div>', unsafe_allow_html=True)
    col_map1, col_map2 = st.columns(2)

    columns = list(raw_df.columns)
    # Smart default for text column
    default_text_idx = 0
    for idx, c in enumerate(columns):
        if any(keyword in c.lower() for keyword in ["text", "ad", "message", "body", "content"]):
            default_text_idx = idx
            break

    with col_map1:
        text_col = st.selectbox(
            "Select Advertisement Text Column (Required)",
            options=columns,
            index=default_text_idx,
            help="The column containing the text of advertisements to analyze.",
        )

    # Smart default for label column
    label_options = ["None (Unlabeled Data)"] + columns
    default_label_idx = 0
    for idx, c in enumerate(columns):
        if any(keyword in c.lower() for keyword in ["risk", "label", "target", "class"]):
            default_label_idx = idx + 1
            break

    with col_map2:
        label_col_choice = st.selectbox(
            "Select Ground Truth Label Column (Optional)",
            options=label_options,
            index=default_label_idx,
            help="If evaluating model against known labels, select the ground-truth column.",
        )
        label_col = None if label_col_choice == "None (Unlabeled Data)" else label_col_choice

    # Run Batch Button
    st.markdown('<div class="section-header">3. Execute Batch Triage</div>', unsafe_allow_html=True)
    include_deep_hf = st.checkbox(
        "Enable DistilBERT Transformer Inference (Deep analysis; higher per-row processing time)",
        value=False,
        help="When checked, runs both TF-IDF ML baseline and DistilBERT Sequence Classifier for consensus evaluation.",
    )
    b_col1, b_col2, _ = st.columns([1.5, 1, 3])
    with b_col1:
        execute_clicked = st.button("⚡ Run Batch Analysis", type="primary", use_container_width=True)
    with b_col2:
        if st.button("✕ Reset", use_container_width=True):
            st.session_state.batch_raw_df = None
            st.session_state.batch_results_df = None
            st.session_state.batch_filename = ""
            st.rerun()

    if execute_clicked:
        progress_bar = st.progress(0, text="Starting batch analysis…")
        status_text = st.empty()

        def update_progress(current, total):
            pct = int((current / total) * 100)
            progress_bar.progress(pct, text=f"Analyzing row {current:,} of {total:,} ({pct}%)…")

        results_df = run_batch_analysis(
            df=raw_df,
            text_column=text_col,
            label_column=label_col,
            progress_callback=update_progress,
            include_hf=include_deep_hf,
        )
        progress_bar.progress(100, text="Batch analysis completed!")
        status_text.success(f"✓ Successfully triaged {len(results_df):,} advertisement records.")
        st.session_state.batch_results_df = results_df

# ── Step 4: Display & Export Results ──────────────────────────────────
results_df = st.session_state.batch_results_df
if results_df is not None:
    st.markdown('<div class="section-header">4. Batch Analysis Results & Triage Summary</div>', unsafe_allow_html=True)

    # High-level metrics
    total_analyzed = len(results_df)
    valid_rows = len(results_df[results_df["validation_status"] == "OK"])
    critical_count = len(results_df[results_df["risk_level"] == "Critical"])
    high_count = len(results_df[results_df["risk_level"] == "High"])
    medium_count = len(results_df[results_df["risk_level"] == "Medium"])
    low_count = len(results_df[results_df["risk_level"] == "Low"])

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.metric("Total Records", f"{total_analyzed:,}")
    with m2:
        st.metric("Critical Alerts", f"{critical_count:,}", delta=f"{(critical_count/total_analyzed*100):.1f}%" if total_analyzed else None, delta_color="inverse")
    with m3:
        st.metric("High Risk", f"{high_count:,}", delta=f"{(high_count/total_analyzed*100):.1f}%" if total_analyzed else None, delta_color="inverse")
    with m4:
        st.metric("Medium Risk", f"{medium_count:,}")
    with m5:
        st.metric("Low / Benign", f"{low_count:,}")

    # Filters
    st.markdown("##### Filter Results View")
    f_col1, f_col2 = st.columns([1, 2])
    with f_col1:
        level_filter = st.multiselect(
            "Filter by Final Risk Tier",
            options=["Critical", "High", "Medium", "Low"],
            default=["Critical", "High", "Medium", "Low"],
        )
    with f_col2:
        search_query = st.text_input("Search filtered records", placeholder="Filter by text, category, or contact info…")

    filtered_df = results_df[results_df["risk_level"].isin(level_filter)]
    if search_query:
        sq = search_query.lower()
        filtered_df = filtered_df[
            filtered_df["original_text"].str.lower().str.contains(sq, na=False) |
            filtered_df["matched_categories"].str.lower().str.contains(sq, na=False) |
            filtered_df["phone_numbers"].str.lower().str.contains(sq, na=False)
        ]

    st.markdown(f"Displaying **{len(filtered_df):,}** of **{len(results_df):,}** records:")
    st.dataframe(filtered_df, use_container_width=True)

    # Safe Export Section
    st.markdown('<div class="section-header">5. Export Sanitized Intelligence Report</div>', unsafe_allow_html=True)
    st.caption("🛡️ **Formula Injection Protection:** Cells starting with `=, +, -, @, \\t, \\r` are safely prepended with a tab delimiter to neutralize spreadsheet code execution in Microsoft Excel, LibreOffice, and Google Sheets.")

    csv_data = export_safe_csv(results_df)
    st.download_button(
        label="📥 Download Sanitized Results CSV",
        data=csv_data,
        file_name=f"tracefin_batch_analysis_{st.session_state.batch_filename or 'export'}",
        mime="text/csv",
        type="primary",
        use_container_width=True,
    )

render_disclaimer()
