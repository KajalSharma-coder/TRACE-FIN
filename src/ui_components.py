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
    padding: 0.25rem 0.75rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}}

/* ── Engine / Demo banner ───────────────────────────────────────── */
.demo-banner {{
    background: rgba(6, 182, 212, 0.12);
    border: 1px solid rgba(6, 182, 212, 0.35);
    border-radius: 6px;
    padding: 0.5rem 1rem;
    color: {COLORS["accent"]};
    font-size: 0.8rem;
    font-weight: 600;
    text-align: center;
    letter-spacing: 1px;
    margin-bottom: 1rem;
}}

.warning-banner {{
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
        st.caption(f"{APP_CATEGORY} · Console")
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
                <div><strong>Engine:</strong> Rule-Based Detector (Phase 2)</div>
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
        st.caption("Explainable rule-based triage.")
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
    """Return HTML for a risk-level badge with standardized level lookup."""
    key = risk_level.strip().capitalize() if risk_level else "Low"
    cfg = RISK_LEVELS.get(key, RISK_LEVELS.get(risk_level.upper(), RISK_LEVELS["Low"]))
    label = cfg.get("label", key)
    color = cfg.get("color", "#64748b")
    return (
        f'<span class="badge" style="background: {color}20; '
        f'color: {color}; border: 1px solid {color}40;">'
        f'{label}</span>'
    )


def render_status_badge(status: str) -> str:
    """Return HTML for an investigation-status badge."""
    color = STATUS_COLORS.get(status, COLORS["text_muted"])
    return (
        f'<span class="badge" style="background: {color}20; '
        f'color: {color}; border: 1px solid {color}40;">'
        f'{status}</span>'
    )


def render_ml_badge(ml_prediction: str | None, confidence: float | None = None) -> str:
    """Return HTML for a machine-learning classification badge with confidence."""
    if not ml_prediction:
        return (
            '<span class="badge" style="background: rgba(100, 116, 139, 0.2); '
            'color: #94a3b8; border: 1px solid #475569;">'
            'ML: Unscored</span>'
        )

    pred = str(ml_prediction).strip()
    if pred == "High Risk":
        color = "#f97316"
        bg = "rgba(249, 115, 22, 0.2)"
        border = "rgba(249, 115, 22, 0.4)"
    elif pred == "Safe":
        color = "#22c55e"
        bg = "rgba(34, 197, 94, 0.2)"
        border = "rgba(34, 197, 94, 0.4)"
    else:
        color = "#38bdf8"
        bg = "rgba(56, 189, 248, 0.2)"
        border = "rgba(56, 189, 248, 0.4)"

    conf_text = f" ({confidence * 100:.1f}%)" if confidence is not None else ""
    return (
        f'<span class="badge" style="background: {bg}; '
        f'color: {color}; border: 1px solid {border}; font-weight: 600;">'
        f'ML: {pred}{conf_text}</span>'
    )


def render_consensus_card(
    rule_level: str,
    ml_prediction: str | None,
    rule_score: float | int = 0,
    ml_confidence: float | None = None,
) -> None:
    """Render a dual-engine consensus or divergence indicator card."""
    if not ml_prediction:
        return

    is_rule_threat = str(rule_level).capitalize() in ("Critical", "High", "Medium")
    is_ml_threat = (str(ml_prediction).strip() == "High Risk")

    if is_rule_threat and is_ml_threat:
        border_col = "rgba(239, 68, 68, 0.6)"
        bg_col = "rgba(239, 68, 68, 0.12)"
        title_col = "#f87171"
        icon = "🚨"
        title = "Dual-Engine Consensus: Confirmed High Risk Threat"
        desc = (
            f"Both detection engines agree. Rule-based heuristic scored {rule_score}/100 ({rule_level}), "
            f"and ML baseline classified as High Risk"
            + (f" ({ml_confidence * 100:.1f}% confidence)." if ml_confidence else ".")
        )
    elif not is_rule_threat and not is_ml_threat:
        border_col = "rgba(34, 197, 94, 0.5)"
        bg_col = "rgba(34, 197, 94, 0.10)"
        title_col = "#4ade80"
        icon = "✓"
        title = "Dual-Engine Consensus: Benign / Safe Transaction"
        desc = "Both detection systems independently agree that this text contains standard, benign transaction language."
    elif is_rule_threat and not is_ml_threat:
        border_col = "rgba(249, 115, 22, 0.6)"
        bg_col = "rgba(249, 115, 22, 0.12)"
        title_col = "#fb923c"
        icon = "⚠️"
        title = "Engine Divergence: Rule-Based Threat Alert (ML Blind Spot)"
        desc = (
            f"Rule-based engine detected suspicious patterns ({rule_level}, score {rule_score}/100), "
            f"while ML baseline predicted Safe. This is common with novel phrasing outside the synthetic training templates. "
            f"Prioritize explainable rule triggers."
        )
    else:
        border_col = "rgba(234, 179, 8, 0.6)"
        bg_col = "rgba(234, 179, 8, 0.12)"
        title_col = "#facc15"
        icon = "⚠️"
        title = "Engine Divergence: ML Anomaly Alert (Heuristic Divergence)"
        desc = (
            f"ML baseline flagged this text as High Risk"
            + (f" ({ml_confidence * 100:.1f}%)," if ml_confidence else ",")
            + " but rule heuristics found no specific violation. Verify vocabulary tokens for spurious correlation."
        )

    st.markdown(
        f"""
        <div style="background: {bg_col}; border: 1px solid {border_col}; border-radius: 8px; padding: 1rem 1.2rem; margin: 1rem 0;">
            <div style="font-size: 0.95rem; font-weight: 600; color: {title_col}; margin-bottom: 0.3rem;">
                {icon} {title}
            </div>
            <div style="font-size: 0.85rem; color: #cbd5e1; line-height: 1.5;">
                {desc}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_demo_banner() -> None:
    """Show the rule-based analyzer and preliminary triage indicator."""
    st.markdown(
        '<div class="demo-banner">◆ EXPLAINABLE RULE-BASED DETECTION ENGINE — '
        'Automated preliminary indicators for investigator triage. Not definitive proof of criminal activity. ◆</div>',
        unsafe_allow_html=True,
    )


def render_disclaimer() -> None:
    """Show the human-review disclaimer."""
    st.markdown(
        '<div class="disclaimer">'
        '<strong>Important Note for Investigators:</strong> A suspicious signal is not proof of a crime. '
        'All flagged advertisements require human review, contextual evaluation, and verified due process '
        'before any conclusions or enforcement actions are drawn. This platform serves as investigative decision support — it does '
        'not replace human judgement.</div>',
        unsafe_allow_html=True,
    )


def render_record_detail(record: dict) -> None:
    """Display a full record detail panel with explainable evidence and extracted indicators."""
    st.markdown(f'<div class="result-header">Case Record: {record["record_id"]}</div>',
                unsafe_allow_html=True)

    # Top-level indicators
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown("**Rule Risk Score**")
        score_val = record.get("risk_score", 0)
        # Format as int
        score_int = int(score_val) if isinstance(score_val, (int, float)) else score_val
        st.markdown(f"### {score_int} / 100")
    with col2:
        st.markdown("**Rule Risk Level**")
        st.markdown(render_risk_badge(record.get("risk_level", "Low")), unsafe_allow_html=True)
    with col3:
        st.markdown("**ML Prediction**")
        st.markdown(render_ml_badge(record.get("ml_prediction"), record.get("ml_confidence")), unsafe_allow_html=True)
    with col4:
        st.markdown("**Investigation Status**")
        st.markdown(render_status_badge(record.get("investigation_status", "Open")),
                    unsafe_allow_html=True)

    # Review Recommendation
    rec = record.get("review_recommendation") or (
        "Investigator Review Recommended" if record.get("review_required")
        else "No Immediate Review Indicated"
    )
    is_req = record.get("review_required")
    risk_lvl = record.get("risk_level", "Low").capitalize()
    if risk_lvl == "Critical":
        bg_color, border_color, text_color = "rgba(239, 68, 68, 0.15)", "rgba(239, 68, 68, 0.4)", "#f87171"
    elif risk_lvl == "High":
        bg_color, border_color, text_color = "rgba(249, 115, 22, 0.15)", "rgba(249, 115, 22, 0.4)", "#fb923c"
    elif risk_lvl == "Medium":
        bg_color, border_color, text_color = "rgba(234, 179, 8, 0.15)", "rgba(234, 179, 8, 0.4)", "#facc15"
    else:
        bg_color, border_color, text_color = "rgba(34, 197, 94, 0.15)", "rgba(34, 197, 94, 0.4)", "#4ade80"

    icon = "⚠️" if is_req else "✓"

    st.markdown(
        f"""
        <div style="background: {bg_color}; border: 1px solid {border_color}; border-radius: 6px; padding: 0.8rem 1rem; margin: 0.8rem 0; color: {text_color}; font-size: 0.88rem;">
            <strong>{icon} Review Recommendation:</strong> {rec}
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Dual-Engine Consensus or Divergence
    if record.get("ml_prediction"):
        render_consensus_card(
            rule_level=record.get("risk_level", "Low"),
            ml_prediction=record.get("ml_prediction"),
            rule_score=record.get("risk_score", 0),
            ml_confidence=record.get("ml_confidence"),
        )

    # Original Ad Text
    st.markdown('<div class="section-header">Original Advertisement Text</div>',
                unsafe_allow_html=True)
    st.code(record["ad_text"], language=None)

    # Analysis Details
    st.markdown('<div class="section-header">Analysis Details & Explainable Evidence</div>',
                unsafe_allow_html=True)

    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("**Submitted At**")
        st.write(record.get("submitted_at", "—"))
        st.markdown("**Analysis Mode**")
        mode = record.get("analysis_mode", "rule_based")
        st.write(mode.upper())
        st.markdown("**Review Required**")
        st.write("Yes" if record.get("review_required") else "No")

    with col_b:
        st.markdown("**Matched Categories**")
        cats = record.get("matched_categories", [])
        if cats:
            for c in cats:
                st.write(f"• {c}")
        else:
            st.write("None detected (Clean/Legitimate)")

    # Evidence details: supports both Phase 2 list format and legacy Phase 1 dict format
    evidence = record.get("evidence", [])
    if evidence:
        st.markdown("**Explainable Evidence & Rule Matches**")
        if isinstance(evidence, list):
            for item in evidence:
                st.markdown(f"• {item}")
        elif isinstance(evidence, dict):
            for cat_name, items in evidence.items():
                st.markdown(f"*{cat_name}:*")
                for item in items:
                    st.write(f"  — `{item}`")

    # Extracted indicators (4 columns: URLs, Emails, Phones, Payment IDs)
    st.markdown('<div class="section-header">Extracted Contact & Payment Indicators</div>',
                unsafe_allow_html=True)
    ind_col1, ind_col2, ind_col3, ind_col4 = st.columns(4)

    with ind_col1:
        st.markdown("**Extracted URLs**")
        urls = record.get("urls", [])
        if urls:
            for u in urls:
                st.write(f"`{u}`")
        else:
            st.caption("None extracted")

    with ind_col2:
        st.markdown("**Extracted Emails**")
        emails = record.get("emails", [])
        if emails:
            for em in emails:
                st.write(f"`{em}`")
        else:
            st.caption("None extracted")

    with ind_col3:
        st.markdown("**Phone Numbers**")
        phones = record.get("phone_numbers", [])
        if phones:
            for p in phones:
                st.write(f"`{p}`")
        else:
            st.caption("None extracted")

    with ind_col4:
        st.markdown("**Payment IDs (UPI/Crypto)**")
        pids = record.get("payment_identifiers", [])
        if pids:
            for pid in pids:
                st.write(f"`{pid}`")
        else:
            st.caption("None extracted")

    # Capabilities Roadmap
    st.markdown('<div class="section-header">Advanced Engine Capabilities & Roadmap</div>',
                unsafe_allow_html=True)
    f_col1, f_col2, f_col3 = st.columns(3)
    with f_col1:
        st.markdown("**ML Text Classifier (Phase 3)**")
        if record.get("ml_prediction"):
            ver = record.get("ml_model_version") or "v1.0"
            st.caption(f"✓ **Active** ({ver})")
        else:
            st.caption("⚡ Baseline Trained (Available)")
    with f_col2:
        st.markdown("**OCR / Image Text (Phase 4)**")
        st.caption("⏳ *Scheduled for Phase 4*")
    with f_col3:
        st.markdown("**Network / Lead Graph (Phase 4)**")
        st.caption("⏳ *Scheduled for Phase 4*")

    if record.get("is_synthetic"):
        st.info("ℹ️ Synthetic Demonstration Record — Fictional advertisement for workflow testing.")

    render_disclaimer()
