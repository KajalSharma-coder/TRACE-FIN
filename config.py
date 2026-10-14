"""
TRACE//FIN — Application Configuration
Central configuration for paths, constants, and design tokens.
"""

from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
ASSETS_DIR = PROJECT_ROOT / "assets"
MODELS_DIR = PROJECT_ROOT / "models"
DB_PATH = DATA_DIR / "tracefin.db"
MODEL_PATH = MODELS_DIR / "financial_ad_classifier.joblib"
METRICS_PATH = MODELS_DIR / "model_metrics.json"
DATASET_PATH = DATA_DIR / "back.dataset.csv"
SPAM_DATASET_PATH = DATA_DIR / "cleaned_spam_dataset.csv"
HF_MODEL_DIR = MODELS_DIR / "hf_financial_ad_classifier"
HF_METRICS_PATH = HF_MODEL_DIR / "metadata.json"

# Ensure directories exist at import time
DATA_DIR.mkdir(exist_ok=True)
MODELS_DIR.mkdir(exist_ok=True)

# ── Product Identity ───────────────────────────────────────────────────
APP_NAME = "TRACE//FIN"
APP_TAGLINE = "Detect signals. Connect evidence. Prioritize investigations."
APP_CATEGORY = "Financial Threat Intelligence"
APP_VERSION = "0.5.0-phase5"

# ── Standardized Risk Levels (Phase 2) ─────────────────────────────────
# Engineering thresholds:
# Low: 0–24, Medium: 25–49, High: 50–74, Critical: 75–100
RISK_LEVELS = {
    "Critical": {"label": "Critical", "color": "#ef4444", "min_score": 75, "max_score": 100},
    "High":     {"label": "High",     "color": "#f97316", "min_score": 50, "max_score": 74},
    "Medium":   {"label": "Medium",   "color": "#eab308", "min_score": 25, "max_score": 49},
    "Low":      {"label": "Low",      "color": "#22c55e", "min_score": 0,  "max_score": 24},
}

# Backward-compatibility aliases for legacy uppercase/minimal lookups
RISK_LEVELS["CRITICAL"] = RISK_LEVELS["Critical"]
RISK_LEVELS["HIGH"]     = RISK_LEVELS["High"]
RISK_LEVELS["MEDIUM"]   = RISK_LEVELS["Medium"]
RISK_LEVELS["LOW"]      = RISK_LEVELS["Low"]
RISK_LEVELS["MINIMAL"]  = RISK_LEVELS["Low"]
RISK_LEVELS["Minimal"]  = RISK_LEVELS["Low"]
RISK_LEVELS["HIGH RISK"]   = RISK_LEVELS["High"]
RISK_LEVELS["MEDIUM RISK"] = RISK_LEVELS["Medium"]
RISK_LEVELS["LOW RISK"]    = RISK_LEVELS["Low"]

# Standard ordered list of risk tiers (highest to lowest)
STANDARDIZED_RISK_TIERS = ["Critical", "High", "Medium", "Low"]

# ── Investigation Statuses ─────────────────────────────────────────────
CASE_STATUSES = ["Open", "Reviewing", "Escalated", "Closed"]

STATUS_COLORS = {
    "Open":      "#3b82f6",
    "Reviewing": "#eab308",
    "Escalated": "#ef4444",
    "Closed":    "#64748b",
}

# ── Analysis Modes ─────────────────────────────────────────────────────
ANALYSIS_MODE_RULE_BASED = "rule_based"
ANALYSIS_MODE_DEMO = "demo"

# ── UI Design Tokens ──────────────────────────────────────────────────
COLORS = {
    "bg_primary":    "#0f1724",
    "bg_secondary":  "#1a2332",
    "bg_card":       "#1e293b",
    "bg_card_hover": "#243348",
    "border":        "#334155",
    "text_primary":  "#f1f5f9",
    "text_secondary":"#94a3b8",
    "text_muted":    "#64748b",
    "accent":        "#06b6d4",
    "accent_dim":    "#0e7490",
    "success":       "#22c55e",
    "warning":       "#eab308",
    "danger":        "#ef4444",
    "info":          "#3b82f6",
}
