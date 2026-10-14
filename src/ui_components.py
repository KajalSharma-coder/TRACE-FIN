"""
TRACE//FIN — Reusable UI Components
Shared Streamlit components and CSS for consistent design.
"""

import streamlit as st

from config import (
    APP_NAME, APP_TAGLINE, APP_CATEGORY,
    COLORS, RISK_LEVELS, STATUS_COLORS, CASE_STATUSES,
)


# ── Global CSS ─────────────────────────────────────────────────────────

def inject_global_css() -> None:
    """Inject the global stylesheet once per page."""
    st.markdown(_GLOBAL_CSS, unsafe_allow_html=True)


_GLOBAL_CSS = f"""
<style>
/* ── Base overrides ─────────────────────────────────────────────── */
.stApp {{
    background-color: {COLORS["bg_primary"]};
}}

/* Sidebar styling */
section[data-testid="stSidebar"] {{
    background-color: {COLORS["bg_secondary"]} !important;
    border-right: 1px solid {COLORS["border"]};
}}

section[data-testid="stSidebar"] .stMarkdown h1 {{
    color: {COLORS["accent"]} !important;
    font-size: 1.5rem !important;
    letter-spacing: 2px;
    margin-bottom: 0 !important;
}}

/* ── Metric cards ───────────────────────────────────────────────── */
.metric-card {{
    background: {COLORS["bg_card"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 8px;
    padding: 1.2rem 1.4rem;
    text-align: center;
    transition: border-color 0.2s;
}}
.metric-card:hover {{
    border-color: {COLORS["accent_dim"]};
}}
.metric-value {{
    font-size: 2rem;
    font-weight: 700;
    color: {COLORS["text_primary"]};
    line-height: 1.2;
}}
.metric-label {{
    font-size: 0.8rem;
    color: {COLORS["text_secondary"]};
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 0.3rem;
}}

/* ── Status / risk badges ───────────────────────────────────────── */
.badge {{
    display: inline-block;
    padding: 0.2rem 0.7rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}}

/* ── Demo banner ────────────────────────────────────────────────── */
.demo-banner {{
    background: rgba(234, 179, 8, 0.12);
    border: 1px solid rgba(234, 179, 8, 0.3);
    border-radius: 6px;
    padding: 0.5rem 1rem;
    color: #eab308;
    font-size: 0.8rem;
    font-weight: 600;
    text-align: center;
    letter-spacing: 1px;
    margin-bottom: 1rem;
}}

/* ── Card container ─────────────────────────────────────────────── */
.card {{
    background: {COLORS["bg_card"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1rem;
}}

/* ── Result panel ───────────────────────────────────────────────── */
.result-panel {{
    background: {COLORS["bg_card"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 8px;
    padding: 1.5rem;
    margin-top: 1rem;
}}

.result-header {{
    font-size: 1.15rem;
    font-weight: 600;
    color: {COLORS["text_primary"]};
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid {COLORS["border"]};
}}

/* ── Section headers ────────────────────────────────────────────── */
.section-header {{
    color: {COLORS["text_primary"]};
    font-size: 1.05rem;
    font-weight: 600;
    margin: 1.4rem 0 0.7rem 0;
    padding-bottom: 0.3rem;
    border-bottom: 1px solid {COLORS["border"]};
}}

/* ── Disclaimer ─────────────────────────────────────────────────── */
.disclaimer {{
    background: rgba(100, 116, 139, 0.1);
    border-left: 3px solid {COLORS["text_muted"]};
    padding: 0.8rem 1rem;
    color: {COLORS["text_secondary"]};
    font-size: 0.82rem;
    border-radius: 0 6px 6px 0;
    margin-top: 1.2rem;
    line-height: 1.5;
}}

/* Hide default Streamlit metric styling that clashes */
[data-testid="stMetricValue"] {{
    font-size: 1.8rem !important;
}}

/* Table tweaks */
.stDataFrame {{
    border-radius: 8px;
    overflow: hidden;
}}
</style>
"""


# ── Sidebar ────────────────────────────────────────────────────────────

def render_sidebar() -> None:
    """Render the consistent sidebar with branding and navigation."""
    with st.sidebar:
        st.markdown(f"# {APP_NAME}")
        st.caption(f"{APP_CATEGORY} · Platform")
        st.markdown("---")

        # Navigation
        st.page_link("app.py", label="📊 Dashboard")
        st.page_link("pages/1_Analyze_Advertisement.py", label="🔍 Analyze Advertisement")
        st.page_link("pages/2_Investigation_Cases.py", label="📋 Investigation Cases")
        st.page_link("pages/3_Data_Explorer.py", label="🗂️ Data Explorer")

        st.markdown("---")

        # Application Status
        st.markdown("**Application Status**")
        st.markdown(
            f"""
            <div style="font-size: 0.8rem; color: {COLORS['text_secondary']}; line-height: 1.6; background: {COLORS['bg_card']}; padding: 0.75rem; border-radius: 6px; border: 1px solid {COLORS['border']};">
                <div><span style="color: {COLORS['success']};">●</span> <strong>Status:</strong> Operational</div>
                <div><strong>Engine:</strong> Rule-Based Demo (v0.1.0)</div>
                <div><strong>Storage:</strong> SQLite WAL (Persistent)</div>
                <div><strong>Environment:</strong> Local / Sandbox</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("")
        st.markdown(
            '<div class="demo-banner">◆ DEMO DATA MODE ◆</div>',
            unsafe_allow_html=True,
        )
        st.caption("Pattern-based scoring for demo only.")
        st.caption("Not a trained ML model.")


# ── Component Helpers ──────────────────────────────────────────────────

def render_metric_card(label: str, value: int | str, color: str | None = None) -> str:
    """Return HTML for a styled metric card."""
    val_style = f'color: {color};' if color else ''
    return f"""
    <div class="metric-card">
        <div class="metric-value" style="{val_style}">{value}</div>
        <div class="metric-label">{label}</div>
    </div>
    """


def render_risk_badge(risk_level: str) -> str:
    """Return HTML for a risk-level badge."""
    cfg = RISK_LEVELS.get(risk_level, RISK_LEVELS["MINIMAL"])
    return (
        f'<span class="badge" style="background: {cfg["color"]}20; '
        f'color: {cfg["color"]}; border: 1px solid {cfg["color"]}40;">'
        f'{cfg["label"]}</span>'
    )


def render_status_badge(status: str) -> str:
    """Return HTML for an investigation-status badge."""
    color = STATUS_COLORS.get(status, COLORS["text_muted"])
    return (
        f'<span class="badge" style="background: {color}20; '
        f'color: {color}; border: 1px solid {color}40;">'
        f'{status}</span>'
    )


def render_demo_banner() -> None:
    """Show the demo-data indicator."""
    st.markdown(
        '<div class="demo-banner">◆ DEMO ANALYSIS — Pattern-based scoring for demonstration only. '
        'Not a trained model or validated fraud detector. ◆</div>',
        unsafe_allow_html=True,
    )


def render_disclaimer() -> None:
    """Show the human-review disclaimer."""
    st.markdown(
        '<div class="disclaimer">'
        '<strong>Important Note for Investigators:</strong> A suspicious signal is not proof of a crime. '
        'All flagged advertisements require human review, contextual evaluation, and verified due process '
        'before any conclusions are drawn. This platform serves as investigative decision support — it does '
        'not replace human judgement.</div>',
        unsafe_allow_html=True,
    )


def render_record_detail(record: dict) -> None:
    """Display a full record detail panel."""
    st.markdown(f'<div class="result-header">Case Record: {record["record_id"]}</div>',
                unsafe_allow_html=True)

    # Top-level indicators
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("**Risk Score**")
        st.markdown(f"### {record['risk_score']} / 100")
    with col2:
        st.markdown("**Risk Level**")
        st.markdown(render_risk_badge(record["risk_level"]), unsafe_allow_html=True)
    with col3:
        st.markdown("**Investigation Status**")
        st.markdown(render_status_badge(record["investigation_status"]),
                    unsafe_allow_html=True)

    # Review Recommendation
    rec = record.get("review_recommendation") or (
        "Investigator Review Recommended" if record.get("review_required")
        else "No Immediate Review Indicated"
    )
    is_req = record.get("review_required")
    bg_color = "rgba(239, 68, 68, 0.12)" if is_req else "rgba(34, 197, 94, 0.12)"
    border_color = "rgba(239, 68, 68, 0.35)" if is_req else "rgba(34, 197, 94, 0.35)"
    text_color = "#f87171" if is_req else "#4ade80"
    icon = "⚠️" if is_req else "✓"

    st.markdown(
        f"""
        <div style="background: {bg_color}; border: 1px solid {border_color}; border-radius: 6px; padding: 0.8rem 1rem; margin: 0.8rem 0; color: {text_color}; font-size: 0.88rem;">
            <strong>{icon} Review Recommendation:</strong> {rec}
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Original Ad Text
    st.markdown('<div class="section-header">Original Advertisement Text</div>',
                unsafe_allow_html=True)
    st.code(record["ad_text"], language=None)

    # Analysis Details
    st.markdown('<div class="section-header">Analysis Details & Evidence</div>',
                unsafe_allow_html=True)

    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("**Submitted At**")
        st.write(record.get("submitted_at", "—"))
        st.markdown("**Analysis Mode**")
        st.write(record.get("analysis_mode", "demo").upper())
        st.markdown("**Review Required**")
        st.write("Yes" if record.get("review_required") else "No")

    with col_b:
        st.markdown("**Matched Categories**")
        cats = record.get("matched_categories", [])
        if cats:
            for c in cats:
                st.write(f"• {c}")
        else:
            st.write("None detected")

    # Evidence details
    evidence = record.get("evidence", {})
    if evidence:
        st.markdown("**Extracted Evidence Snippets**")
        for cat_name, items in evidence.items():
            st.markdown(f"*{cat_name}:*")
            for item in items:
                st.write(f"  — `{item}`")

    # Extracted indicators
    st.markdown('<div class="section-header">Extracted Contact & Payment Indicators</div>',
                unsafe_allow_html=True)
    ind_col1, ind_col2, ind_col3 = st.columns(3)
    with ind_col1:
        st.markdown("**Extracted URLs**")
        urls = record.get("urls", [])
        if urls:
            for u in urls:
                st.write(f"`{u}`")
        else:
            st.caption("None extracted")
    with ind_col2:
        st.markdown("**Extracted Phone Numbers**")
        phones = record.get("phone_numbers", [])
        if phones:
            for p in phones:
                st.write(f"`{p}`")
        else:
            st.caption("None extracted")
    with ind_col3:
        st.markdown("**Extracted Payment Identifiers**")
        pids = record.get("payment_identifiers", [])
        if pids:
            for pid in pids:
                st.write(f"`{pid}`")
        else:
            st.caption("None extracted")

    # Unsupported / Future Capabilities (Master Prompt Section 7)
    st.markdown('<div class="section-header">Advanced Engine Capabilities (Future Phases)</div>',
                unsafe_allow_html=True)
    f_col1, f_col2 = st.columns(2)
    with f_col1:
        st.markdown("**OCR / Text Inside Image**")
        st.caption("⏳ *Not implemented (Scheduled for Phase 3)*")
    with f_col2:
        st.markdown("**Cross-Ad Relationship Leads**")
        st.caption("⏳ *Not implemented (Scheduled for Phase 4)*")

    if record.get("is_synthetic"):
        st.info("ℹ️ Synthetic Demonstration Record — Fictional advertisement for workflow testing.")

    render_disclaimer()
