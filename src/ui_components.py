"""
TRACE//FIN — Reusable UI Components
Shared Streamlit components and CSS for consistent design.
"""

from html import escape
import streamlit as st

from config import COLORS, RISK_LEVELS, STATUS_COLORS, CASE_STATUSES


# ── Global CSS ─────────────────────────────────────────────────────────

def inject_global_css() -> None:
    """Inject the global stylesheet once per page."""
    st.markdown(_GLOBAL_CSS, unsafe_allow_html=True)


_GLOBAL_CSS = f"""
<style>
/* TRACE//FIN navy and cyan application shell */
.stApp {{
    background: radial-gradient(ellipse at 15% 0%, rgba(6,182,212,.08), transparent 35%), {COLORS["bg_primary"]};
    color: {COLORS["text_primary"]};
}}
.block-container {{ max-width: 1440px; padding-top: 2rem; padding-bottom: 3rem; }}
.auth-brand {{ color: {COLORS["accent"]}; font-size: 1.5rem; font-weight: 750; letter-spacing: .12em; }}
[data-testid="stHeader"] {{ background: rgba(15,23,36,.88); }}
[data-testid="stMarkdownContainer"] p, [data-testid="stCaptionContainer"] {{ line-height: 1.55; }}
input, textarea {{ border-radius: 8px !important; }}
div.stButton > button, div.stFormSubmitButton > button {{
    border-radius: 8px; min-height: 2.65rem; font-weight: 600;
    border: 1px solid rgba(6,182,212,.45); transition: background .15s ease, border-color .15s ease;
}}
div.stButton > button:hover, div.stFormSubmitButton > button:hover {{ border-color: {COLORS["accent"]}; }}
div[data-testid="stExpander"] {{ border-color: {COLORS["border"]}; border-radius: 10px; }}

/* ── Base overrides ─────────────────────────────────────────────── */
.stApp {{
    background-color: {COLORS["bg_primary"]};
}}

/* Sidebar shell */
section[data-testid="stSidebar"] {{
    width: clamp(280px, 24vw, 300px) !important;
    min-width: clamp(280px, 24vw, 300px) !important;
    background: linear-gradient(180deg, #091725 0%, {COLORS["bg_secondary"]} 42%, #08131f 100%) !important;
    border-right: 1px solid rgba(19, 214, 192, .16);
    box-shadow: 12px 0 36px rgba(0, 0, 0, .12);
}}
section[data-testid="stSidebar"] [data-testid="stSidebarContent"] {{ overflow-x:hidden; }}
section[data-testid="stSidebar"] [data-testid="stVerticalBlock"] {{ gap:.55rem; }}
section[data-testid="stSidebar"] .sidebar-brand {{
    padding:.55rem .2rem .85rem; border-bottom:1px solid rgba(124,160,179,.14); margin-bottom:.2rem;
}}
section[data-testid="stSidebar"] .sidebar-brand-name {{ color:#edf7fb; font-size:1.08rem; font-weight:780; letter-spacing:.17em; white-space:nowrap; }}
section[data-testid="stSidebar"] .sidebar-brand-name span {{ color:#13d6c0; }}
section[data-testid="stSidebar"] .sidebar-brand-subtitle {{ color:#8398a9; font-size:.68rem; letter-spacing:.045em; margin-top:.3rem; }}
section[data-testid="stSidebar"] .sidebar-profile {{
    display:flex; align-items:center; gap:.7rem; min-width:0; padding:.72rem .68rem;
    border:1px solid rgba(108,149,170,.17); border-radius:11px; background:rgba(14,34,50,.72);
}}
section[data-testid="stSidebar"] .sidebar-avatar {{
    width:38px; height:38px; flex:0 0 38px; display:grid; place-items:center; border-radius:50%;
    color:#06201f; font-size:.9rem; font-weight:750; background:linear-gradient(145deg,#35dfc9,#139f99);
    box-shadow:0 0 18px rgba(19,214,192,.15);
}}
section[data-testid="stSidebar"] .sidebar-profile-copy {{ min-width:0; display:flex; flex-direction:column; gap:.17rem; }}
section[data-testid="stSidebar"] .sidebar-profile-copy strong {{ color:#e5eff4; font-size:.83rem; font-weight:650; overflow-wrap:anywhere; }}
section[data-testid="stSidebar"] .sidebar-profile-copy span {{ color:#8b9eac; font-size:.69rem; overflow-wrap:anywhere; }}
section[data-testid="stSidebar"] .st-key-tracefin_logout button {{ min-height:2.35rem; color:#bacbd4; background:transparent; border:1px solid rgba(126,157,174,.25); font-size:.78rem; }}
section[data-testid="stSidebar"] .st-key-tracefin_logout button:hover {{ color:#f3fbfd; background:rgba(19,214,192,.08); border-color:rgba(19,214,192,.48); }}
section[data-testid="stSidebar"] .sidebar-group-label {{ color:#6f8898; font-size:.62rem; font-weight:700; letter-spacing:.16em; padding:.32rem .55rem .05rem; }}
section[data-testid="stSidebar"] [data-testid="stPageLink"] {{ margin:0; }}
section[data-testid="stSidebar"] [data-testid="stPageLink-NavLink"] {{
    position:relative; display:flex; align-items:center; box-sizing:border-box; min-height:42px; width:100%;
    gap:.62rem; padding:.55rem .68rem .55rem .82rem; border:1px solid transparent; border-radius:8px;
    color:#aebfc9; font-size:.81rem; line-height:1.3; text-decoration:none; white-space:normal; overflow-wrap:anywhere;
    transition:color .15s ease, background .15s ease, border-color .15s ease;
}}
section[data-testid="stSidebar"] [data-testid="stPageLink-NavLink"]:hover {{ color:#eaf8f8; background:rgba(19,214,192,.075); border-color:rgba(19,214,192,.12); }}
section[data-testid="stSidebar"] [data-testid="stPageLink-NavLink"]:focus-visible {{ outline:2px solid #20cdbb; outline-offset:2px; }}
section[data-testid="stSidebar"] [data-testid="stPageLink-NavLink"][aria-current="page"] {{
    color:#e7fbf8; background:linear-gradient(90deg,rgba(17,181,164,.18),rgba(17,181,164,.055)); border-color:rgba(19,214,192,.17);
}}
section[data-testid="stSidebar"] [data-testid="stPageLink-NavLink"][aria-current="page"]::before {{
    content:""; position:absolute; left:-1px; top:7px; bottom:7px; width:2px; border-radius:2px;
    background:#19d5c0; box-shadow:0 0 10px rgba(25,213,192,.42);
}}
section[data-testid="stSidebar"] .sidebar-helper {{ color:#728897; font-size:.66rem; line-height:1.5; padding:.45rem .55rem .15rem; overflow-wrap:anywhere; }}
section[data-testid="stSidebar"] .sidebar-status-title {{ color:#dce8ee; font-size:.8rem; font-weight:650; margin:0 0 .48rem; }}
section[data-testid="stSidebar"] .sidebar-status-card {{
    padding:.72rem .76rem; border:1px solid rgba(102,143,163,.18); border-radius:10px;
    background:linear-gradient(145deg,rgba(13,32,47,.94),rgba(8,23,36,.94)); color:#9db0bc;
    font-size:.67rem; line-height:1.55; overflow-wrap:anywhere;
}}
section[data-testid="stSidebar"] .sidebar-status-row {{ display:flex; align-items:center; gap:.45rem; margin-bottom:.38rem; color:#d6e4e9; }}
section[data-testid="stSidebar"] .sidebar-status-row:last-child {{ margin-bottom:0; }}
section[data-testid="stSidebar"] .sidebar-status-dot {{ width:7px; height:7px; flex:0 0 7px; border-radius:50%; background:{COLORS["success"]}; box-shadow:0 0 9px currentColor; }}
section[data-testid="stSidebar"] .sidebar-status-dot.is-down {{ background:{COLORS["danger"]}; }}
section[data-testid="stSidebar"] .sidebar-status-key {{ color:#728a99; }}
section[data-testid="stSidebar"] .sidebar-model-note {{ color:#758b99; font-size:.64rem; line-height:1.45; padding:.4rem .3rem 0; overflow-wrap:anywhere; }}
@media (max-width:700px) {{
    section[data-testid="stSidebar"] {{ width:min(88vw,300px) !important; min-width:min(88vw,300px) !important; }}
}}

/* ── Metric cards ───────────────────────────────────────────────── */
.metric-card {{
    background: {COLORS["bg_card"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 12px;
    padding: 1.1rem 1.25rem;
    min-height: 110px;
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
    border-radius: 12px;
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

def _logout_callback() -> None:
    from src.auth import clear_authenticated_session, revoke_auth_session
    token = st.session_state.get("auth_token")
    revoke_auth_session(token)
    clear_authenticated_session(st.session_state)
    st.session_state["_auth_cookie_delete"] = True
    st.session_state["_logout_redirect"] = True
    st.query_params.clear()


def require_authenticated_user() -> bool:
    """Compatibility wrapper for the page guard in the auth module."""
    from src.auth import require_authenticated_user as guard
    return guard()


def render_sidebar() -> None:
    """Render the consistent sidebar with branding and navigation."""
    with st.sidebar:
        st.markdown(
            '<div class="sidebar-brand"><div class="sidebar-brand-name">TRACE<span>//</span>FIN</div>'
            '<div class="sidebar-brand-subtitle">Financial Threat Intelligence</div></div>',
            unsafe_allow_html=True,
        )
        identity = st.session_state.get("auth_user") or {}
        if identity:
            display_name = str(identity.get("name") or "Investigator")
            email = str(identity.get("email") or "")
            initial = escape(display_name[:1].upper() or "I")
            st.markdown(
                '<div class="sidebar-profile">'
                f'<div class="sidebar-avatar" aria-hidden="true">{initial}</div>'
                f'<div class="sidebar-profile-copy"><strong>{escape(display_name)}</strong>'
                f'<span>{escape(email)}</span></div></div>',
                unsafe_allow_html=True,
            )
            st.button("Log out", key="tracefin_logout", on_click=_logout_callback,
                      use_container_width=True, type="secondary", icon=":material/logout:")

        st.markdown('<div class="sidebar-group-label">OVERVIEW</div>', unsafe_allow_html=True)
        st.page_link("app.py", label="Dashboard", icon=":material/dashboard:")
        st.markdown('<div class="sidebar-group-label">INVESTIGATION</div>', unsafe_allow_html=True)
        st.page_link("pages/1_Analyze_Advertisement.py", label="Analyze advertisement", icon=":material/search:")
        st.page_link("pages/4_Image_Analysis.py", label="Image / OCR analysis", icon=":material/image:")
        st.page_link("pages/5_Batch_CSV_Analysis.py", label="Batch CSV analysis", icon=":material/upload_file:")
        st.page_link("pages/2_Investigation_Cases.py", label="Case management", icon=":material/folder_open:")
        st.page_link("pages/3_Data_Explorer.py", label="Data explorer", icon=":material/database:")
        st.markdown(
            '<div class="sidebar-helper">Inspect advertisement links from the Analyze Advertisement workflow.</div>',
            unsafe_allow_html=True,
        )

        # Application Status
        from src.database import check_database_connection
        from config import ACTIVE_MODEL_PATH
        from src.ml_model import load_model
        from src.hf_model import get_hf_model_status
        db_info = check_database_connection()
        tfidf_pipeline = load_model(model_path=ACTIVE_MODEL_PATH)
        tfidf_loaded = bool(
            tfidf_pipeline is not None
            and hasattr(tfidf_pipeline, "named_steps")
            and {"tfidf", "clf"}.issubset(tfidf_pipeline.named_steps)
        )
        hf_status = get_hf_model_status()
        tfidf_label = "trained pipeline loaded" if tfidf_loaded else "unavailable / invalid artifact"
        hf_label = hf_status.get("status", "unavailable")
        hf_base = hf_status.get("base_model") or "base model unknown"
        storage_label = "Neon PostgreSQL (SSL)" if db_info.get("is_postgres") else "SQLite WAL (Local)"
        status_text = "Operational" if db_info.get("connected") else "Degraded (No DB)"

        st.markdown(
            '<div class="sidebar-status-title">Application Status</div>'
            '<div class="sidebar-status-card">'
            f'<div class="sidebar-status-row"><span class="sidebar-status-dot{"" if db_info.get("connected") else " is-down"}"></span><strong>{escape(status_text)}</strong></div>'
            '<div><span class="sidebar-status-key">Rule detector:</span> heuristic rules (not ML)</div>'
            f'<div><span class="sidebar-status-key">TF-IDF:</span> {escape(tfidf_label)}</div>'
            f'<div><span class="sidebar-status-key">Transformer:</span> {escape(str(hf_base))} · {escape(str(hf_label))}</div>'
            f'<div><span class="sidebar-status-key">Storage:</span> {escape(storage_label)}</div>'
            f'<div><span class="sidebar-status-key">Records:</span> {int(db_info.get("record_count", 0) or 0)} loaded</div>'
            '</div>',
            unsafe_allow_html=True,
        )

        st.markdown(
            '<div class="sidebar-model-note">Risk decisions combine rule evidence with available local model predictions.</div>',
            unsafe_allow_html=True,
        )
        if not tfidf_loaded or not hf_status.get("available"):
            st.markdown(
                '<div class="sidebar-model-note">One or more statistical models are unavailable; results show this in engine status.</div>',
                unsafe_allow_html=True,
            )


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


def render_hf_badge(hf_prediction: str | None, confidence: float | None = None) -> str:
    """Return HTML for a Hugging Face DistilBERT classification badge with confidence."""
    if not hf_prediction:
        return (
            '<span class="badge" style="background: rgba(100, 116, 139, 0.2); '
            'color: #94a3b8; border: 1px solid #475569;">'
            'DistilBERT: Unscored</span>'
        )

    pred = str(hf_prediction).strip()
    if pred == "High Risk":
        color = "#ef4444"
        bg = "rgba(239, 68, 68, 0.2)"
        border = "rgba(239, 68, 68, 0.4)"
    elif pred == "Safe":
        color = "#22c55e"
        bg = "rgba(34, 197, 94, 0.2)"
        border = "rgba(34, 197, 94, 0.4)"
    else:
        color = "#a855f7"
        bg = "rgba(168, 85, 247, 0.2)"
        border = "rgba(168, 85, 247, 0.4)"

    conf_text = f" ({confidence * 100:.1f}%)" if confidence is not None else ""
    return (
        f'<span class="badge" style="background: {bg}; '
        f'color: {color}; border: 1px solid {border}; font-weight: 600;">'
        f'DistilBERT: {pred}{conf_text}</span>'
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
    col1, col2, col3, col4, col5 = st.columns(5)
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
        st.markdown("**TF-IDF ML**")
        st.markdown(render_ml_badge(record.get("ml_prediction"), record.get("ml_confidence")), unsafe_allow_html=True)
    with col4:
        st.markdown("**DistilBERT**")
        st.markdown(render_hf_badge(record.get("hf_prediction"), record.get("hf_confidence")), unsafe_allow_html=True)
    with col5:
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

    evidence = record.get("evidence", [])
    st.markdown("**Explainable Evidence & Rule Matches**")
    if evidence:
        if isinstance(evidence, list):
            for item in evidence:
                st.markdown(f"• {item}")
        elif isinstance(evidence, dict):
            for cat_name, items in evidence.items():
                st.markdown(f"*{cat_name}:*")
                for item in items:
                    st.write(f"  — `{item}`")
    else:
        st.info("No configured rules matched.")

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
    f_col1, f_col2, f_col3, f_col4 = st.columns(4)
    with f_col1:
        st.markdown("**TF-IDF Classifier (Phase 3)**")
        if record.get("ml_prediction"):
            ver = record.get("ml_model_version") or "v1.0"
            st.caption(f"✓ **Active** ({ver})")
        else:
            st.caption("⚡ Baseline Trained (Available)")
    with f_col2:
        st.markdown("**DistilBERT (Phase 4)**")
        if record.get("hf_prediction"):
            hver = record.get("hf_model_version") or "distilbert-v1.0"
            st.caption(f"✓ **Active** ({hver})")
        else:
            st.caption("⚡ Transformer Ready")
    with f_col3:
        st.markdown("**OCR Image Analysis (Phase 4)**")
        st.caption("✓ **Active** (Tesseract 5.x)")
    with f_col4:
        st.markdown("**Batch CSV Analysis (Phase 4)**")
        st.caption("✓ **Active** (Formula-Safe)")

    if record.get("is_synthetic"):
        st.info("ℹ️ Synthetic Demonstration Record — Fictional advertisement for workflow testing.")

    render_disclaimer()
