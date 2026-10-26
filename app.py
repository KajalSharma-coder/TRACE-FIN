"""TRACE//FIN entry point: local authentication and investigator dashboard."""

import streamlit as st

from config import APP_NAME, APP_TAGLINE, APP_CATEGORY, COLORS, RISK_LEVELS, STANDARDIZED_RISK_TIERS
from src.auth import (
    AuthStoreError, DuplicateAccountError, authenticate_user, create_user,
    create_auth_session, init_auth_store, set_authenticated_session,
    restore_authenticated_session,
)
from src.dashboard import load_dashboard_snapshot
from src.database import init_db, get_all_records
from src.public_home import dashboard_preview_markup
from src.ui_components import (
    inject_global_css, render_sidebar, render_metric_card,
    render_disclaimer, render_record_detail,
)

st.set_page_config(
    page_title=f"{APP_NAME} — Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
inject_global_css()

_PUBLIC_HOME_CSS = """
<style>
.stApp:has(.st-key-public_home) [data-testid="stMainBlockContainer"],.stApp:has(.st-key-public_home) .block-container { box-sizing:border-box; width:100% !important; max-width:none !important; margin:0 !important; padding:0 !important; }
.stApp:has(.st-key-public_home) section[data-testid="stSidebar"] { display:none !important; }
.stApp:has(.st-key-public_home) [data-testid="stHeader"] { display:none !important; }
.st-key-public_home { width:100%; max-width:none; box-sizing:border-box; overflow:hidden; background:radial-gradient(ellipse at 72% 20%, rgba(0,196,166,.10), transparent 34%), #030d19; margin:0; padding:0 0 1.5rem; }
.st-key-public_home_content { width:min(92vw,1760px); max-width:1760px; min-width:0; box-sizing:border-box; margin-inline:auto; }
.st-key-public_home .public-nav { min-height: 72px; display:flex; align-items:center; gap:36px; border-bottom:1px solid rgba(43,119,137,.28); }
.st-key-public_home .public-wordmark { color:#11d6c0; font-weight:800; font-size:1.25rem; letter-spacing:.18em; white-space:nowrap; }
.st-key-public_home .public-navlinks { display:flex; align-items:center; gap:34px; flex:1; }
.st-key-public_home .public-nav a { color:#d6e4ee; text-decoration:none; font-size:.94rem; transition:color .18s; }
.st-key-public_home .public-nav a:hover { color:#16dbc2; }
.st-key-public_home .public-nav .public-signin { border:1px solid #0ccdbb; border-radius:9px; padding:10px 19px; color:#eaf9fa; }
.st-key-public_home .public-hero { display:grid; width:100%; max-width:none; min-width:0; box-sizing:border-box; grid-template-columns:minmax(0,9fr) minmax(0,11fr); align-items:center; gap:clamp(24px,3.2vw,48px); padding:40px 0 56px; }
.st-key-public_home .public-hero-copy,.st-key-public_home .public-hero-preview { min-width:0; max-width:100%; box-sizing:border-box; }
.st-key-public_home .hero-kicker { color:#c2d4e1; font-size:.75rem; letter-spacing:.25em; font-weight:700; margin-bottom:22px; }
.st-key-public_home .hero-kicker:before { content:""; display:inline-block; width:34px; height:2px; background:#d7ad60; margin:0 18px 4px 0; }
.st-key-public_home .hero-title { color:#f4f8fc; max-width:100%; font-size:clamp(2.65rem,4.3vw,4.65rem); line-height:1.04; font-weight:760; letter-spacing:-.045em; word-break:normal; overflow-wrap:normal; hyphens:none; margin:0 0 24px; }
.st-key-public_home .hero-title span { color:#16d5bb; background:linear-gradient(90deg,#10cbb9 5%,#70e1bd 65%,#e9b968); -webkit-background-clip:text; background-clip:text; -webkit-text-fill-color:transparent; }
.st-key-public_home .hero-copy { color:#b8c9d8; font-size:1.06rem; line-height:1.75; max-width:510px; margin:0 0 28px; }
.st-key-public_home .hero-actions { display:flex; flex-wrap:wrap; gap:14px; }
.st-key-public_home .hero-actions a { text-decoration:none; border-radius:9px; padding:13px 20px; font-weight:650; }
.st-key-public_home .hero-primary { background:linear-gradient(120deg,#09bca9,#0fcba9); color:#03121b; box-shadow:0 0 26px rgba(0,207,177,.15); }
.st-key-public_home .hero-secondary { border:1px solid #c69548; color:#f3e5cb; }
.st-key-public_home .hero-footnote { color:#8298aa; font-size:.78rem; margin-top:18px; }
.st-key-public_home .preview-shell { border:1px solid rgba(0,220,194,.70); border-radius:15px; background:linear-gradient(140deg,rgba(5,25,42,.98),rgba(3,16,31,.98)); box-shadow:0 20px 75px rgba(0,0,0,.32),0 0 42px rgba(0,208,181,.07); overflow:hidden; position:relative; }
.st-key-public_home .preview-topbar { height:48px; display:flex; align-items:center; justify-content:space-between; border-bottom:1px solid rgba(73,128,147,.24); padding:0 18px; }
.st-key-public_home .preview-logo { color:#12d6c1; font-weight:800; font-size:.78rem; letter-spacing:.13em; }
.st-key-public_home .preview-online { color:#a8bdcb; font-size:.58rem; letter-spacing:.07em; background:#102c3b; padding:6px 9px; border-radius:20px; }
.st-key-public_home .preview-online i { display:inline-block; width:6px; height:6px; border-radius:50%; background:#13d9b6; margin-right:5px; }
.st-key-public_home .preview-content { display:grid; grid-template-columns:150px minmax(0,1fr); min-height:370px; }
.st-key-public_home .preview-side { border-right:1px solid rgba(73,128,147,.2); padding:13px 9px; }
.st-key-public_home .preview-nav { color:#9cb1c0; font-size:.62rem; padding:10px 8px; border-radius:6px; margin-bottom:4px; white-space:nowrap; }
.st-key-public_home .preview-nav.active { color:#e5fbf8; background:linear-gradient(90deg,rgba(0,192,171,.25),rgba(0,192,171,.05)); }
.st-key-public_home .preview-main { padding:19px 19px 16px; min-width:0; }
.st-key-public_home .preview-heading { display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:15px; }
.st-key-public_home .preview-heading small,.st-key-public_home .preview-muted { color:#7f9bad; font-size:.57rem; letter-spacing:.1em; }
.st-key-public_home .preview-heading h3 { color:#e5eff5; font-size:1rem; margin:3px 0 0; font-weight:600; }
.st-key-public_home .preview-live-label { color:#71cfc0; font-size:.47rem; letter-spacing:.06em; text-align:right; max-width:185px; }
.st-key-public_home .preview-metrics { display:grid; grid-template-columns:1fr .92fr 1fr; gap:10px; }
.st-key-public_home .preview-score-card,.st-key-public_home .preview-activity,.st-key-public_home .preview-distribution { border:1px solid rgba(61,118,139,.28); border-radius:8px; background:rgba(6,30,48,.66); min-height:112px; padding:11px; }
.st-key-public_home .preview-score-card strong { display:block; color:#eff9fd; font-weight:500; font-size:1.6rem; margin:7px 0; }
.st-key-public_home .preview-score-card strong b { font-weight:650; }
.st-key-public_home .preview-score-card strong small { color:#8197a8; font-size:.65rem; }
.st-key-public_home .score-track,.st-key-public_home .preview-bar { height:5px; background:#102e3d; border-radius:8px; overflow:hidden; margin:5px 0 8px; }
.st-key-public_home .score-track i,.st-key-public_home .preview-bar i { display:block; height:100%; border-radius:8px; background:linear-gradient(90deg,#0ed7ad,#eac05e,#ed5c5f); }
.st-key-public_home .preview-score-card .preview-muted:last-child { font-size:.48rem; letter-spacing:0; }
.st-key-public_home .preview-activity strong { display:block; color:#f2f8fb; font-size:1.55rem; margin-top:6px; }
.st-key-public_home .preview-activity small { color:#718b9d; font-size:.55rem; }
.st-key-public_home .sparkline { display:flex; align-items:end; gap:4px; height:22px; border-bottom:1px solid #173548; margin-top:3px; }
.st-key-public_home .sparkline i { width:10%; background:linear-gradient(#ed5e58,#9a3638); border-radius:4px 4px 0 0; }
.st-key-public_home .sparkline i:nth-child(1),.st-key-public_home .sparkline i:nth-child(5) {height:35%}.st-key-public_home .sparkline i:nth-child(2),.st-key-public_home .sparkline i:nth-child(7) {height:58%}.st-key-public_home .sparkline i:nth-child(3),.st-key-public_home .sparkline i:nth-child(8) {height:44%}.st-key-public_home .sparkline i:nth-child(4),.st-key-public_home .sparkline i:nth-child(9) {height:82%}.st-key-public_home .sparkline i:nth-child(6) {height:100%}
.st-key-public_home .preview-bar-label { display:flex; justify-content:space-between; color:#b8c9d6; font-size:.56rem; margin-top:7px; }
.st-key-public_home .preview-bar-label small { color:#8da2b1; font-size:.53rem; }
.st-key-public_home .preview-bar { height:4px; margin:3px 0 0; }
.st-key-public_home .preview-bar .bar-high {background:#ef5e60}.st-key-public_home .preview-bar .bar-medium {background:#e9ac46}.st-key-public_home .preview-bar .bar-low {background:#21c99d}
.st-key-public_home .preview-recent-head { display:flex; justify-content:space-between; color:#849eae; font-size:.55rem; letter-spacing:.1em; border-bottom:1px solid rgba(61,118,139,.22); padding:16px 1px 8px; }
.st-key-public_home .preview-recent-head span:last-child { color:#4d9d94; font-size:.48rem; }
.st-key-public_home .preview-row { display:grid; grid-template-columns:24px minmax(0,1fr) auto 42px; gap:8px; align-items:center; min-height:39px; border-bottom:1px solid rgba(61,118,139,.13); color:#d5e2ea; font-size:.58rem; }
.st-key-public_home .preview-doc { width:21px; height:21px; display:grid; place-items:center; border-radius:50%; background:#103044; color:#69d7cb; }
.st-key-public_home .preview-name { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.st-key-public_home .preview-risk { padding:4px 7px; border-radius:5px; white-space:nowrap; font-size:.5rem; }
.st-key-public_home .risk-high {color:#ffb5ae;background:rgba(211,66,75,.2)}.st-key-public_home .risk-medium {color:#f4cc84;background:rgba(198,131,44,.2)}.st-key-public_home .risk-low {color:#7ce4c2;background:rgba(26,163,125,.2)}
.st-key-public_home .preview-score { color:#a9bbc8; text-align:right; font-size:.52rem; }
.st-key-public_home .preview-empty { color:#92a8b7; font-size:.75rem; padding:22px 2px; }
.st-key-public_home .feature-strip { display:grid; grid-template-columns:repeat(3,1fr); border-top:1px solid rgba(49,109,127,.24); border-bottom:1px solid rgba(49,109,127,.24); padding:28px 0; }
.st-key-public_home .feature-card { display:flex; gap:16px; padding:8px 26px; border-right:1px solid rgba(49,109,127,.35); }
.st-key-public_home .feature-card:first-child {padding-left:0}.st-key-public_home .feature-card:last-child {border:0}
.st-key-public_home .feature-icon { width:48px;height:48px;flex:0 0 48px;display:grid;place-items:center;border:1px solid #0ba995;border-radius:50%;color:#1cddc3;font-size:1.2rem;box-shadow:0 0 20px rgba(11,169,149,.09); }
.st-key-public_home .feature-card h3 {color:#ecf4f8;font-size:.92rem;margin:2px 0 7px;font-weight:650}.st-key-public_home .feature-card p {color:#8fa7b8;font-size:.76rem;line-height:1.55;margin:0;}
.st-key-public_home .public-section {padding:48px 0 24px; scroll-margin-top:22px;}
.st-key-public_home .public-section h2 {color:#eff7fb;font-size:1.65rem;letter-spacing:-.025em;margin:0 0 10px;}
.st-key-public_home .public-section > p {color:#9fb2c0;max-width:720px;font-size:.92rem;line-height:1.7;margin:0;}
.st-key-public_home .steps {display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:22px;}
.st-key-public_home .step {border:1px solid rgba(65,120,138,.24);border-radius:10px;padding:17px;background:rgba(7,26,42,.56);}
.st-key-public_home .step b {display:block;color:#17cdb6;font-size:.67rem;letter-spacing:.13em;margin-bottom:8px}.st-key-public_home .step span {color:#dce8ef;font-size:.84rem}.st-key-public_home .step p {color:#91a6b5;font-size:.75rem;line-height:1.55;margin:7px 0 0;}
.st-key-public_home .security-note {border:1px solid rgba(191,153,87,.28);border-radius:10px;padding:17px 19px;margin-top:18px;color:#b9c7ce;background:linear-gradient(105deg,rgba(124,96,45,.09),rgba(5,25,40,.45));font-size:.81rem;line-height:1.7;}
.st-key-public_home .public-footer {display:flex;justify-content:space-between;gap:18px;align-items:center;border-top:1px solid rgba(49,109,127,.28);padding:21px 0 5px;margin-top:40px;color:#8299a9;font-size:.7rem;}
.st-key-public_home .public-footer strong {color:#15cdb9;letter-spacing:.13em}.st-key-public_home .public-footer a {color:#a6b8c5;text-decoration:none}
@media (max-width:1050px) { .st-key-public_home .public-hero{gap:24px;padding:40px 0}.st-key-public_home .preview-shell{max-width:none}.st-key-public_home .preview-content{grid-template-columns:120px minmax(0,1fr)}.st-key-public_home .preview-metrics{grid-template-columns:1fr 1fr}.st-key-public_home .preview-distribution{grid-column:1/-1} }
@media (max-width:820px) { .st-key-public_home_content{width:calc(100% - 36px)}.st-key-public_home .public-hero{grid-template-columns:minmax(0,1fr);gap:30px;padding:38px 0 34px}.st-key-public_home .hero-title{font-size:clamp(2.5rem,7vw,3.8rem)}.st-key-public_home .public-nav{gap:0;justify-content:space-between;min-height:64px}.st-key-public_home .public-navlinks{gap:12px}.st-key-public_home .public-navlinks a{font-size:.69rem}.st-key-public_home .public-nav .public-signin{padding:8px 10px;font-size:.75rem}.st-key-public_home .public-wordmark{font-size:.95rem}.st-key-public_home .preview-content{grid-template-columns:120px minmax(0,1fr)}.st-key-public_home .preview-metrics{grid-template-columns:1fr 1fr}.st-key-public_home .preview-distribution{grid-column:1/-1}.st-key-public_home .feature-strip,.st-key-public_home .steps{grid-template-columns:1fr}.st-key-public_home .feature-card{border-right:0;border-bottom:1px solid rgba(49,109,127,.25);padding:14px 0}.st-key-public_home .feature-card:last-child{border:0}.st-key-public_home .public-footer{align-items:flex-start;flex-direction:column} }
@media (max-width:560px) { .st-key-public_home .public-navlinks{gap:9px}.st-key-public_home .public-navlinks a{font-size:.62rem}.st-key-public_home .public-nav .public-signin{padding:7px 8px;font-size:.68rem}.st-key-public_home .public-wordmark{font-size:.85rem;letter-spacing:.13em}.st-key-public_home .hero-actions{display:grid;grid-template-columns:1fr}.st-key-public_home .hero-actions a{text-align:center}.st-key-public_home .preview-content{grid-template-columns:1fr}.st-key-public_home .preview-side{display:none}.st-key-public_home .preview-main{padding:13px}.st-key-public_home .preview-live-label{font-size:.42rem;max-width:130px} }
</style>
"""


def _load_records():
    init_db()
    return get_all_records()


def render_public_navbar() -> None:
    st.markdown("""
    <nav class="public-nav" aria-label="Main navigation">
      <a class="public-wordmark" href="#top">TRACE//FIN</a>
      <div class="public-navlinks"><a href="#platform">Platform</a><a href="#how-it-works">How it works</a><a href="#security">Security</a></div>
      <a class="public-signin" href="?auth=login">Sign in</a>
    </nav>
    """, unsafe_allow_html=True)


def render_public_hero(snapshot: dict) -> None:
    hero_copy = """
      <div id="top" class="public-hero-copy">
        <div class="hero-kicker">FINANCIAL THREAT INTELLIGENCE</div>
        <h1 class="hero-title">See the risk.<br><span>Stop the fraud.</span></h1>
        <p class="hero-copy">Detect suspicious financial advertisements, surface explainable risk signals and move from analysis to investigation with a clear, evidence-led workflow.</p>
        <div class="hero-actions"><a class="hero-primary" href="?auth=login">→ &nbsp; Enter workspace</a><a class="hero-secondary" href="#platform">Explore platform &nbsp; →</a></div>
        <p class="hero-footnote">Human-led decisions. Evidence stays visible at every step.</p>
      </div>
    """
    preview = dashboard_preview_markup(snapshot)
    st.markdown(
        f'<section class="public-hero" aria-label="TRACE//FIN overview">{hero_copy}'
        f'<div class="public-hero-preview">{preview}</div></section>',
        unsafe_allow_html=True,
    )


def render_feature_cards() -> None:
    st.markdown("""
    <section id="platform" class="feature-strip" aria-label="Platform capabilities">
      <article class="feature-card"><div class="feature-icon" aria-hidden="true">◇</div><div><h3>Explainable risk signals</h3><p>See why an advertisement is flagged with clear evidence and transparent reasoning.</p></div></article>
      <article class="feature-card"><div class="feature-icon" aria-hidden="true">⌘</div><div><h3>Multi-input analysis</h3><p>Review text, URLs, screenshots and CSV batches in one investigation workflow.</p></div></article>
      <article class="feature-card"><div class="feature-icon" aria-hidden="true">▤</div><div><h3>Investigation-ready reports</h3><p>Preserve findings, manage case status and export structured evidence for review.</p></div></article>
    </section>
    """, unsafe_allow_html=True)


def render_how_it_works() -> None:
    st.markdown("""
    <section id="how-it-works" class="public-section">
      <h2>From signal to investigation</h2>
      <p>TRACE//FIN brings analysis and case review into a straightforward investigator workflow.</p>
      <div class="steps">
        <div class="step"><b>01 · INTAKE</b><span>Bring in an advertisement</span><p>Submit text, inspect a URL, review an image with OCR or analyze a CSV batch.</p></div>
        <div class="step"><b>02 · ASSESS</b><span>Review evidence and risk</span><p>Inspect matched indicators, available model predictions and the resulting risk assessment.</p></div>
        <div class="step"><b>03 · INVESTIGATE</b><span>Manage the case</span><p>Save a record, track its status and export structured information for human review.</p></div>
      </div>
    </section>
    """, unsafe_allow_html=True)


def render_security_section() -> None:
    st.markdown("""
    <section id="security" class="public-section">
      <h2>Designed for careful handling</h2>
      <p>Analysis supports investigator judgement; it does not determine guilt or replace verification.</p>
      <div class="security-note"><strong>Privacy-first analysis.</strong> TRACE//FIN keeps the evidence and the reasoning visible. Uploaded images are handled in memory by the existing OCR workflow. Local accounts protect workspace access; current records are shared in the same local workbench.</div>
    </section>
    """, unsafe_allow_html=True)


def render_public_footer() -> None:
    st.markdown("""
    <footer class="public-footer"><span><strong>TRACE//FIN</strong> &nbsp; · &nbsp; Financial advertisement intelligence</span><a href="#security">Privacy-first analysis</a></footer>
    """, unsafe_allow_html=True)


def render_public_home(snapshot: dict) -> None:
    st.markdown(_PUBLIC_HOME_CSS, unsafe_allow_html=True)
    with st.container(key="public_home"):
        with st.container(key="public_home_content"):
            render_public_navbar()
            render_public_hero(snapshot)
            render_feature_cards()
            render_how_it_works()
            render_security_section()
            render_public_footer()


def _signup_callback() -> None:
    state = st.session_state
    try:
        identity = create_user(
            state.get("signup_name", ""), state.get("signup_email", ""),
            state.get("signup_password", ""), state.get("signup_confirm", ""),
        )
        state["_auth_cookie_pending"] = create_auth_session(identity["id"])
        set_authenticated_session(state, identity)
        state.pop("auth_view", None)
        state.pop("auth_error", None)
        st.query_params.clear()
    except (ValueError, DuplicateAccountError) as exc:
        state["auth_error"] = str(exc)
    except AuthStoreError:
        state["auth_error"] = "Local account storage is unavailable. Check local disk access and try again."
    finally:
        state.pop("signup_password", None)
        state.pop("signup_confirm", None)


def _login_callback() -> None:
    state = st.session_state
    try:
        identity = authenticate_user(
            state.get("login_email", ""), state.get("login_password", "")
        )
        if identity:
            state["_auth_cookie_pending"] = create_auth_session(identity["id"])
            set_authenticated_session(state, identity)
            state.pop("auth_error", None)
            st.query_params.clear()
        else:
            state["auth_error"] = "Invalid email or password."
    except AuthStoreError:
        state["auth_error"] = "Local account storage is unavailable. Check local disk access and try again."
    finally:
        state.pop("login_password", None)


def render_auth_screen() -> None:
    """Render login/signup without exposing secrets or relying on an external IDP."""
    _, center, _ = st.columns([1, 1.1, 1])
    with center:
        view = st.session_state.get("auth_view", "login")
        with st.container(border=True):
            st.markdown(f"<div class='auth-brand'>{APP_NAME}</div>", unsafe_allow_html=True)
            st.caption(APP_TAGLINE)
            st.divider()
            if view == "signup":
                st.subheader("Create your account")
                st.caption("Set up local access to the investigator workspace.")
                st.text_input("Name", key="signup_name", max_chars=100, placeholder="Your name")
                st.text_input("Email", key="signup_email", max_chars=254, placeholder="you@example.com")
                st.text_input("Password", type="password", key="signup_password", placeholder="At least 12 characters")
                st.text_input("Confirm password", type="password", key="signup_confirm", placeholder="Re-enter your password")
                st.button("Create account", key="signup_submit", on_click=_signup_callback,
                          type="primary", use_container_width=True)
                if st.session_state.get("auth_error"):
                    st.error(st.session_state["auth_error"])
                if st.button("Already registered? Sign in", key="show_login", use_container_width=True):
                    st.session_state.auth_view = "login"
                    st.query_params["auth"] = "login"
                    st.session_state.pop("auth_error", None)
                    st.rerun()
            else:
                st.subheader("Welcome back")
                st.caption("Sign in to continue to TRACE//FIN.")
                st.text_input("Email", key="login_email", max_chars=254, placeholder="you@example.com")
                st.text_input("Password", type="password", key="login_password", placeholder="Enter your password")
                st.button("Sign in", key="login_submit", on_click=_login_callback,
                          type="primary", use_container_width=True)
                if st.session_state.get("auth_error"):
                    st.error(st.session_state["auth_error"])
                st.divider()
                st.caption("New to TRACE//FIN?")
                if st.button("Create a local account", key="show_signup", use_container_width=True):
                    st.session_state.auth_view = "signup"
                    st.query_params["auth"] = "signup"
                    st.session_state.pop("auth_error", None)
                    st.rerun()
            if st.button("← Back to homepage", key="auth_home", use_container_width=True):
                st.session_state.pop("auth_view", None)
                st.session_state.pop("auth_error", None)
                st.query_params.clear()
                st.rerun()
        st.caption("Local/demo authentication. Workspace records are shared across local accounts.")


try:
    init_auth_store()
except AuthStoreError:
    st.error("TRACE//FIN cannot open its local account store. Check that the data directory is writable.")
    st.stop()

try:
    identity = restore_authenticated_session()
    # If logout originated on the dashboard, this script is already the target
    # homepage; consume the one-shot redirect marker before another page guard.
    st.session_state.pop("_logout_redirect", None)
except AuthStoreError:
    st.error("Local account storage is unavailable. Access is paused until it can be reached.")
    st.stop()
if identity:
    try:
        from src.auth import get_user_by_id, clear_authenticated_session
        current = get_user_by_id(identity.get("id"))
    except AuthStoreError:
        st.error("Local account storage is unavailable. Access is paused until it can be reached.")
        st.stop()
    if current is None:
        clear_authenticated_session(st.session_state)
        identity = None
    else:
        set_authenticated_session(st.session_state, current)
else:
    identity = None

if identity is None:
    requested_auth = st.query_params.get("auth")
    if requested_auth in {"login", "signup"}:
        st.session_state["auth_view"] = requested_auth
        render_auth_screen()
    else:
        st.session_state.pop("auth_view", None)
        st.session_state.pop("auth_error", None)
        public_snapshot, _ = load_dashboard_snapshot(_load_records)
        render_public_home(public_snapshot)
    st.stop()

snapshot, db_error = load_dashboard_snapshot(_load_records)

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

render_sidebar()
st.title("Overview dashboard")
st.caption("A current view of advertisement investigations and risk signals.")
st.markdown("[Analyze a new advertisement](pages/1_Analyze_Advertisement.py)")
if db_error:
    st.warning(db_error)
if snapshot["demo_count"]:
    st.info(f"{snapshot['demo_count']} synthetic demonstration records are present in storage. Dashboard metrics below exclude them.")

if snapshot["total"] == 0:
    st.info("No investigator-submitted analyses yet. Analyze an advertisement to start building this dashboard.")

metric_cols = st.columns(5)
high = snapshot["risk_counts"].get("High", 0) + snapshot["risk_counts"].get("Critical", 0)
for column, label, value, color in zip(
    metric_cols,
    ("Total analyses", "High risk", "Medium risk", "Low risk", "Open cases"),
    (snapshot["total"], high, snapshot["risk_counts"].get("Medium", 0),
     snapshot["risk_counts"].get("Low", 0), snapshot["status_counts"].get("Open", 0)),
    (COLORS["accent"], COLORS["danger"], COLORS["warning"], COLORS["success"], COLORS["info"]),
):
    with column:
        st.markdown(render_metric_card(label, value, color), unsafe_allow_html=True)

chart_col1, chart_col2 = st.columns(2)
with chart_col1:
    st.markdown('<div class="section-header">Risk distribution</div>', unsafe_allow_html=True)
    counts = snapshot["risk_counts"]
    if snapshot["total"]:
        levels = STANDARDIZED_RISK_TIERS
        fig = go.Figure(go.Bar(
            x=[RISK_LEVELS[level]["label"] for level in levels],
            y=[counts.get(level, 0) for level in levels],
            marker_color=[RISK_LEVELS[level]["color"] for level in levels],
        ))
        fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                          font_color=COLORS["text_secondary"], height=300,
                          margin=dict(l=15, r=15, t=10, b=35), showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.caption("Risk distribution will appear after the first saved analysis.")

with chart_col2:
    st.markdown('<div class="section-header">Recent analysis activity</div>', unsafe_allow_html=True)
    if snapshot["activity"]:
        df = pd.DataFrame(snapshot["activity"])
        fig = px.line(df, x="date", y="count", markers=True,
                      labels={"date": "Date", "count": "Analyses"})
        fig.update_traces(line_color=COLORS["accent"], marker_color=COLORS["accent"])
        fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                          font_color=COLORS["text_secondary"], height=300,
                          margin=dict(l=15, r=15, t=10, b=35))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.caption("Activity will appear after analyses are saved.")

st.markdown('<div class="section-header">Frequently observed threat categories</div>', unsafe_allow_html=True)
if snapshot["category_counts"]:
    categories = sorted(snapshot["category_counts"].items(), key=lambda item: item[1], reverse=True)
    category_fig = go.Figure(go.Bar(
        x=[count for _, count in categories],
        y=[name for name, _ in categories],
        orientation="h",
        marker_color=COLORS["accent_dim"],
    ))
    category_fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        font_color=COLORS["text_secondary"], height=max(220, len(categories) * 38),
        margin=dict(l=15, r=15, t=10, b=20), yaxis=dict(autorange="reversed"),
    )
    st.plotly_chart(category_fig, use_container_width=True)
else:
    st.caption("No saved threat categories yet.")

st.markdown('<div class="section-header">Recent analyses</div>', unsafe_allow_html=True)
recent = snapshot["recent"]
if recent:
    display = [{
        "Record ID": r["record_id"],
        "Advertisement": (r.get("ad_text") or "")[:90],
        "Risk score": r.get("risk_score", 0),
        "Risk level": r.get("risk_level", "—"),
        "Status": r.get("investigation_status", "—"),
        "Submitted": (r.get("submitted_at") or "")[:16].replace("T", " "),
    } for r in recent]
    st.dataframe(pd.DataFrame(display), use_container_width=True, hide_index=True)
    selected_id = st.selectbox("Inspect a saved analysis", ["— Select —"] + [r["record_id"] for r in recent])
    if selected_id != "— Select —":
        selected = next(r for r in recent if r["record_id"] == selected_id)
        with st.expander(f"Analysis details · {selected_id}"):
            render_record_detail(selected)
else:
    st.caption("No recent investigator-submitted records to show.")

st.markdown('<div class="section-header">Workspace</div>', unsafe_allow_html=True)
col1, col2, col3 = st.columns(3)
with col1:
    st.page_link("pages/1_Analyze_Advertisement.py", label="Analyze advertisement", icon="🔍", use_container_width=True)
with col2:
    st.page_link("pages/2_Investigation_Cases.py", label="Manage cases", icon="📋", use_container_width=True)
with col3:
    st.page_link("pages/3_Data_Explorer.py", label="Explore records", icon="🗂️", use_container_width=True)
render_disclaimer()
