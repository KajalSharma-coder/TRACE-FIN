"""
TRACE//FIN — Data Explorer Page
Comprehensive database browser, granular multi-filter triage, dossier inspection, and forensic CSV export.
"""

import io
from datetime import datetime

import streamlit as st
import pandas as pd

from config import APP_NAME, CASE_STATUSES, STANDARDIZED_RISK_TIERS, COLORS
from src.database import init_db, search_records, get_record, _deserialize_list
from src.sample_data import seed_demo_data
from src.ui_components import (
    inject_global_css, render_sidebar, render_demo_banner,
    render_record_detail, render_disclaimer,
)

# ── Page Config ────────────────────────────────────────────────────────
st.set_page_config(
    page_title=f"{APP_NAME} — Data Explorer",
    page_icon="🗂️",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()
seed_demo_data()
inject_global_css()
render_sidebar()

# ── Header ─────────────────────────────────────────────────────────────
st.markdown("# 🗂️ Intelligence Data Explorer")
st.caption("Browse, query, filter, inspect, and export all ingested financial advertisement intelligence records")
render_demo_banner()

# ── Search & Filters ──────────────────────────────────────────────────
st.markdown('<div class="section-header">Query & Granular Filtering</div>',
            unsafe_allow_html=True)

f_col1, f_col2, f_col3 = st.columns([2, 1, 1])

with f_col1:
    search_text = st.text_input(
        "Free Text Query",
        placeholder="Search by Record ID (TF-...) or keywords ('UPI', 'telegram', 'ATM', 'instant')...",
        key="explorer_search_query",
    )

with f_col2:
    risk_filter = st.selectbox(
        "Risk Classification",
        ["All"] + STANDARDIZED_RISK_TIERS,
        key="explorer_risk_filter",
    )

with f_col3:
    status_filter = st.selectbox(
        "Investigation Lifecycle Status",
        ["All"] + CASE_STATUSES,
        key="explorer_status_filter",
    )

# ── Query Records ──────────────────────────────────────────────────────
records = search_records(
    query=search_text,
    risk_level=risk_filter if risk_filter != "All" else None,
    status=status_filter if status_filter != "All" else None,
)

# ── Results Table ──────────────────────────────────────────────────────
st.markdown(f'<div class="section-header">Ingested Records ({len(records)} matching)</div>',
            unsafe_allow_html=True)

if records:
    # Build display dataframe
    display_rows = []
    for r in records:
        ml_pred = r.get("ml_prediction")
        conf = r.get("ml_confidence")
        ml_display = f"{ml_pred} ({conf*100:.0f}%)" if ml_pred and conf else (ml_pred or "—")
        display_rows.append({
            "Record ID": r["record_id"],
            "Text Preview": (r["ad_text"][:75] + "…") if len(r["ad_text"]) > 75 else r["ad_text"],
            "Risk Score": int(r["risk_score"]) if isinstance(r["risk_score"], (int, float)) else r["risk_score"],
            "Risk Level": r["risk_level"],
            "ML Pred": ml_display,
            "Status": r["investigation_status"],
            "Matched Categories": ", ".join(_deserialize_list(r.get("matched_categories", []))) or "None",
            "URLs": len(_deserialize_list(r.get("urls", []))),
            "Emails": len(_deserialize_list(r.get("emails", []))),
            "Phones": len(_deserialize_list(r.get("phone_numbers", []))),
            "Payment IDs": len(_deserialize_list(r.get("payment_identifiers", []))),
            "Submitted": r["submitted_at"][:16].replace("T", " "),
            "Demo Record": "Yes" if r.get("is_synthetic") else "No",
        })

    df = pd.DataFrame(display_rows)
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Risk Score": st.column_config.ProgressColumn(
                min_value=0, max_value=100, format="%.0f",
            ),
        },
    )

    # ── Forensic CSV Export ────────────────────────────────────────────
    st.markdown('<div class="section-header">Data Export</div>', unsafe_allow_html=True)

    export_rows = []
    for r in records:
        export_rows.append({
            "Record ID": r["record_id"],
            "Advertisement Text": r["ad_text"],
            "Risk Score": int(r["risk_score"]) if isinstance(r["risk_score"], (int, float)) else r["risk_score"],
            "Risk Level": r["risk_level"],
            "ML Prediction": r.get("ml_prediction", ""),
            "ML Confidence": r.get("ml_confidence", ""),
            "Review Required": "Yes" if r.get("review_required") else "No",
            "Review Recommendation": r.get("review_recommendation", ""),
            "Matched Categories": "; ".join(_deserialize_list(r.get("matched_categories", []))),
            "Extracted URLs": "; ".join(_deserialize_list(r.get("urls", []))),
            "Extracted Emails": "; ".join(_deserialize_list(r.get("emails", []))),
            "Extracted Phone Numbers": "; ".join(_deserialize_list(r.get("phone_numbers", []))),
            "Extracted Payment IDs": "; ".join(_deserialize_list(r.get("payment_identifiers", []))),
            "Investigation Status": r["investigation_status"],
            "Analysis Mode": r.get("analysis_mode", "rule_based"),
            "Is Synthetic": "Yes" if r.get("is_synthetic") else "No",
            "Submitted At": r["submitted_at"],
        })
    export_df = pd.DataFrame(export_rows)

    csv_buffer = io.StringIO()
    export_df.to_csv(csv_buffer, index=False)
    csv_data = csv_buffer.getvalue()

    st.download_button(
        label=f"⬇ Export {len(records)} Filtered Record(s) as CSV",
        data=csv_data,
        file_name=f"tracefin_intel_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
        use_container_width=False,
    )

    # ── Record Detail View ─────────────────────────────────────────────
    st.markdown('<div class="section-header">Record Dossier Inspection</div>',
                unsafe_allow_html=True)

    record_ids = [r["record_id"] for r in records]
    selected = st.selectbox(
        "Select a record ID to inspect full dossier",
        ["— Select a record —"] + record_ids,
        key="explorer_detail_select",
    )

    if selected and selected != "— Select a record —":
        record = get_record(selected)
        if record:
            with st.expander(f"📄 Record Dossier: {selected}", expanded=True):
                render_record_detail(record)
        else:
            st.error(f"Record {selected} was not found.")

else:
    if search_text or risk_filter != "All" or status_filter != "All":
        st.info("No records matched your search query or active filters. Try broadening your criteria.")
    else:
        st.info(
            "No intelligence records in the database. Use **Analyze Advertisement** "
            "to submit the first advertisement."
        )

render_disclaimer()
