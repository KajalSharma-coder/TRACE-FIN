"""
TRACE//FIN — Investigation Cases Page
Case management: search, filter, view case dossiers, and manage lifecycle status.
"""

import streamlit as st
import pandas as pd

from config import APP_NAME, CASE_STATUSES, RISK_LEVELS, STATUS_COLORS, COLORS
from src.database import (
    init_db, search_records, get_record, update_status,
)
from src.sample_data import seed_demo_data
from src.ui_components import (
    inject_global_css, render_sidebar, render_demo_banner,
    render_record_detail, render_disclaimer,
)

# ── Page Config ────────────────────────────────────────────────────────
st.set_page_config(
    page_title=f"{APP_NAME} — Investigation Cases",
    page_icon="📋",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()
seed_demo_data()
inject_global_css()
render_sidebar()

# ── Header ─────────────────────────────────────────────────────────────
st.markdown("# 📋 Investigation Case Management")
st.caption("Investigator dossier review, triage prioritization, and lifecycle status tracking")
render_demo_banner()

st.markdown(
    '<div class="disclaimer">'
    '<strong>Investigator Mandate:</strong> A suspicious signal is not proof of a crime. '
    'All flagged advertisements require human investigation, contextual evaluation, and verified '
    'due process before any conclusions or enforcement actions are initiated.</div>',
    unsafe_allow_html=True,
)

# ── Search & Filter Controls ───────────────────────────────────────────
st.markdown('<div class="section-header">Case Triage Filters</div>',
            unsafe_allow_html=True)

filter_col1, filter_col2, filter_col3 = st.columns([2, 1, 1])

with filter_col1:
    search_query = st.text_input(
        "Search by Record ID or advertisement keywords",
        placeholder="e.g. TF-A1B2C3D4, 'telegram', 'kyc', 'current account'",
        key="case_search_input",
    )

with filter_col2:
    risk_filter = st.selectbox(
        "Filter by Risk Level",
        ["All"] + list(RISK_LEVELS.keys()),
        key="case_risk_filter_select",
    )

with filter_col3:
    status_filter = st.selectbox(
        "Filter by Case Status",
        ["All"] + CASE_STATUSES,
        key="case_status_filter_select",
    )

# ── Fetch Records ──────────────────────────────────────────────────────
records = search_records(
    query=search_query,
    risk_level=risk_filter if risk_filter != "All" else None,
    status=status_filter if status_filter != "All" else None,
)

# ── Results List ───────────────────────────────────────────────────────
st.markdown(f'<div class="section-header">Case Files ({len(records)} matching)</div>',
            unsafe_allow_html=True)

if records:
    # Summary table
    display_data = []
    for r in records:
        display_data.append({
            "Record ID": r["record_id"],
            "Text Preview": (r["ad_text"][:75] + "…") if len(r["ad_text"]) > 75 else r["ad_text"],
            "Risk Score": r["risk_score"],
            "Risk Level": r["risk_level"],
            "Status": r["investigation_status"],
            "Review Rec": (r.get("review_recommendation") or "")[:45] + "…",
            "Submitted": r["submitted_at"][:16].replace("T", " "),
        })

    df = pd.DataFrame(display_data)
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

    # ── Record Detail & Status Update ──────────────────────────────────
    st.markdown('<div class="section-header">Case Dossier & Status Lifecycle</div>',
                unsafe_allow_html=True)

    record_ids = [r["record_id"] for r in records]

    # Handle pre-selected record if coming from Analyze page
    selected_target = st.session_state.get("selected_case_id")
    default_index = 0
    if selected_target and selected_target in record_ids:
        default_index = record_ids.index(selected_target) + 1

    selected_id = st.selectbox(
        "Select a case record to inspect and manage",
        ["— Select a record —"] + record_ids,
        index=default_index,
        key="case_detail_select_box",
    )

    if selected_id and selected_id != "— Select a record —":
        # Keep session state in sync
        st.session_state["selected_case_id"] = selected_id
        record = get_record(selected_id)

        if record:
            render_record_detail(record)

            # Status update section
            st.markdown('<div class="section-header">Manage Investigation Status</div>',
                        unsafe_allow_html=True)

            status_col1, status_col2, _ = st.columns([1.2, 1, 2.8])
            with status_col1:
                current_status = record["investigation_status"]
                current_idx = CASE_STATUSES.index(current_status) if current_status in CASE_STATUSES else 0
                new_status = st.selectbox(
                    "Transition Status To",
                    CASE_STATUSES,
                    index=current_idx,
                    key=f"status_select_{selected_id}",
                    help="Update the operational lifecycle status of this case file.",
                )
            with status_col2:
                st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
                if st.button("💾 Apply Status Change", type="primary", use_container_width=True):
                    if new_status == current_status:
                        st.info(f"Case status is already '{current_status}'. No change applied.")
                    else:
                        success = update_status(selected_id, new_status)
                        if success:
                            st.success(f"✓ Case {selected_id} updated: **{current_status}** → **{new_status}**.")
                            st.rerun()
                        else:
                            st.error("Failed to update status in database. Please retry.")
        else:
            st.error(f"Record {selected_id} not found in database.")
else:
    if search_query or risk_filter != "All" or status_filter != "All":
        st.info("No cases match your active filter criteria. Try resetting or adjusting the filters.")
    else:
        st.info(
            "No cases exist in the database. Use the **Analyze Advertisement** page to submit "
            "an advertisement for analysis and create the first case."
        )

render_disclaimer()
