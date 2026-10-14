"""
TRACE//FIN — Application Configuration
Central configuration for paths, constants, and design tokens.
"""

from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
ASSETS_DIR = PROJECT_ROOT / "assets"
DB_PATH = DATA_DIR / "tracefin.db"

# Ensure data directory exists at import time
DATA_DIR.mkdir(exist_ok=True)

# ── Product Identity ───────────────────────────────────────────────────
APP_NAME = "TRACE//FIN"
APP_TAGLINE = "Detect signals. Connect evidence. Prioritize investigations."
APP_CATEGORY = "Financial Threat Intelligence"
APP_VERSION = "0.1.0-phase1"

# ── Risk Levels ────────────────────────────────────────────────────────
RISK_LEVELS = {
    "CRITICAL": {"label": "Critical", "color": "#ef4444", "min_score": 80},
    "HIGH":     {"label": "High",     "color": "#f97316", "min_score": 60},
    "MEDIUM":   {"label": "Medium",   "color": "#eab308", "min_score": 40},
    "LOW":      {"label": "Low",      "color": "#22c55e", "min_score": 20},
    "MINIMAL":  {"label": "Minimal",  "color": "#64748b", "min_score": 0},
}

# ── Investigation Statuses ─────────────────────────────────────────────
CASE_STATUSES = ["Open", "Reviewing", "Escalated", "Closed"]

STATUS_COLORS = {
    "Open":      "#3b82f6",
    "Reviewing": "#eab308",
    "Escalated": "#ef4444",
    "Closed":    "#64748b",
}

# ── Demo / Analysis Modes ─────────────────────────────────────────────
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
