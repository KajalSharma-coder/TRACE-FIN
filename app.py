"""
TRACE//FIN — Main Dashboard
Production-Quality Financial Cybercrime Intelligence Console.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from config import APP_NAME, APP_TAGLINE, APP_CATEGORY, COLORS, RISK_LEVELS, STANDARDIZED_RISK_TIERS
from src.database import init_db, get_dashboard_metrics, get_recent_records
from src.sample_data import seed_demo_data
from src.ui_components import (
    inject_global_css, render_sidebar, render_metric_card,
    render_risk_badge, render_status_badge, render_demo_banner,
    render_disclaimer, render_record_detail,
)

# ── Page Config ────────────────────────────────────────────────────────
st.set_page_config(
    page_title=f"{APP_NAME} — Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Initialize ─────────────────────────────────────────────────────────
init_db()
seed_demo_data()
inject_global_css()
render_sidebar()

# ── Header ─────────────────────────────────────────────────────────────
st.markdown(f"# 🛡️ {APP_NAME}")
st.markdown(f"*{APP_TAGLINE}*")
st.caption(f"{APP_CATEGORY} Platform — Cybercrime Intelligence & Financial Access Ad Triage")
render_demo_banner()

# ── Metrics ────────────────────────────────────────────────────────────
metrics = get_dashboard_metrics()

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown(
        render_metric_card("Total Advertisements", metrics["total"], COLORS["accent"]),
        unsafe_allow_html=True,
    )
with col2:
    high_count = metrics["risk_counts"].get("High", 0) + metrics["risk_counts"].get("Critical", 0)
    st.markdown(
        render_metric_card("High-Risk Records", high_count, COLORS["danger"]),
        unsafe_allow_html=True,
    )
with col3:
    med_count = metrics["risk_counts"].get("Medium", 0)
    st.markdown(
        render_metric_card("Medium-Risk Records", med_count, COLORS["warning"]),
        unsafe_allow_html=True,
    )
with col4:
    open_count = metrics["status_counts"].get("Open", 0)
    st.markdown(
        render_metric_card("Open Investigation Cases", open_count, COLORS["info"]),
        unsafe_allow_html=True,
    )

st.markdown("")

# ── Charts ─────────────────────────────────────────────────────────────
chart_col1, chart_col2 = st.columns(2)

# Risk Distribution (Standardized: Critical, High, Medium, Low)
with chart_col1:
    st.markdown('<div class="section-header">Risk Level Distribution</div>',
                unsafe_allow_html=True)
    risk_data = metrics["risk_counts"]
    if risk_data and sum(risk_data.values()) > 0:
        levels = STANDARDIZED_RISK_TIERS  # ["Critical", "High", "Medium", "Low"]
        counts = [risk_data.get(lvl, 0) for lvl in levels]
        colors = [RISK_LEVELS.get(lvl, {}).get("color", "#64748b") for lvl in levels]
        labels = [RISK_LEVELS.get(lvl, {}).get("label", lvl) for lvl in levels]

        fig = go.Figure(data=[go.Bar(
            x=labels, y=counts,
            marker_color=colors,
            text=counts,
            textposition='auto',
            hovertemplate="<b>%{x} Risk</b><br>Dossiers: %{y}<extra></extra>",
        )])
        fig.update_layout(
            plot_bgcolor="rgba(0,0,0,0)",
            paper_bgcolor="rgba(0,0,0,0)",
            font_color=COLORS["text_secondary"],
            margin=dict(l=20, r=20, t=10, b=40),
            height=300,
            xaxis=dict(showgrid=False),
            yaxis=dict(showgrid=True, gridcolor=COLORS["border"], dtick=1),
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No records in database. Analyze an advertisement to populate metrics.")

# Activity Over Time
with chart_col2:
    st.markdown('<div class="section-header">Advertisement Ingestion Activity Over Time</div>',
                unsafe_allow_html=True)
    activity = metrics["activity"]
    if activity:
        df_act = pd.DataFrame(activity)
        fig2 = px.line(
            df_act, x="date", y="count",
            markers=True,
            labels={"date": "Submission Date", "count": "Advertisements"},
        )
        fig2.update_traces(
            line_color=COLORS["accent"],
            marker=dict(color=COLORS["accent"], size=7),
            hovertemplate="<b>%{x}</b><br>Ingested: %{y}<extra></extra>",
        )
        fig2.update_layout(
            plot_bgcolor="rgba(0,0,0,0)",
            paper_bgcolor="rgba(0,0,0,0)",
            font_color=COLORS["text_secondary"],
            margin=dict(l=20, r=20, t=10, b=40),
            height=300,
            xaxis=dict(showgrid=False),
            yaxis=dict(showgrid=True, gridcolor=COLORS["border"], dtick=1),
        )
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No activity data available yet.")

# Top Indicator Categories
st.markdown('<div class="section-header">Most Frequently Observed Threat Categories</div>',
            unsafe_allow_html=True)
cat_counts = metrics["category_counts"]
if cat_counts:
    sorted_cats = sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)
    cat_names = [c[0] for c in sorted_cats]
    cat_vals = [c[1] for c in sorted_cats]

    fig3 = go.Figure(data=[go.Bar(
        x=cat_vals, y=cat_names,
        orientation='h',
        marker_color=COLORS["accent_dim"],
        text=cat_vals,
        textposition='auto',
        hovertemplate="<b>%{y}</b><br>Matches: %{x}<extra></extra>",
    )])
    fig3.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font_color=COLORS["text_secondary"],
        margin=dict(l=20, r=20, t=10, b=20),
        height=max(220, len(cat_names) * 42),
        xaxis=dict(showgrid=True, gridcolor=COLORS["border"], dtick=1),
        yaxis=dict(showgrid=False, autorange="reversed"),
    )
    st.plotly_chart(fig3, use_container_width=True)
else:
    st.info("No threat categories observed yet.")

# ── Recent Activity ────────────────────────────────────────────────────
st.markdown('<div class="section-header">Recent Advertisements & Cases</div>',
            unsafe_allow_html=True)

recent = get_recent_records(10)
if recent:
    display_data = []
    for r in recent:
        ml_pred = r.get("ml_prediction")
        conf = r.get("ml_confidence")
        ml_display = f"{ml_pred} ({conf*100:.0f}%)" if ml_pred and conf else (ml_pred or "—")
        display_data.append({
            "Record ID": r["record_id"],
            "Text Preview": (r["ad_text"][:75] + "…") if len(r["ad_text"]) > 75 else r["ad_text"],
            "Risk Score": int(r["risk_score"]) if isinstance(r["risk_score"], (int, float)) else r["risk_score"],
            "Risk Level": r["risk_level"],
            "ML Pred": ml_display,
            "Status": r["investigation_status"],
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

    # Record detail inspect
    record_ids = [r["record_id"] for r in recent]
    selected_id = st.selectbox(
        "Open record for detailed inspection",
        ["— Select a record —"] + record_ids,
        key="dashboard_inspect_select",
    )
    if selected_id and selected_id != "— Select a record —":
        selected = next((r for r in recent if r["record_id"] == selected_id), None)
        if selected:
            with st.expander(f"📄 Full Case Dossier: {selected_id}", expanded=True):
                render_record_detail(selected)
else:
    st.info("No records found in database. Use **Analyze Advertisement** to submit your first record.")

# ── Quick Action Shortcuts ─────────────────────────────────────────────
st.markdown('<div class="section-header">Investigator Shortcuts</div>',
            unsafe_allow_html=True)
qa_col1, qa_col2, qa_col3 = st.columns(3)
with qa_col1:
    if st.button("🔍 Analyze New Advertisement", use_container_width=True):
        st.switch_page("pages/1_Analyze_Advertisement.py")
with qa_col2:
    if st.button("📋 Open Case Management", use_container_width=True):
        st.switch_page("pages/2_Investigation_Cases.py")
with qa_col3:
    if st.button("🗂️ Browse Data Explorer & Export", use_container_width=True):
        st.switch_page("pages/3_Data_Explorer.py")

render_disclaimer()
