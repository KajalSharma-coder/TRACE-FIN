"""Local SQLite authentication for TRACE//FIN's single-workbench deployment."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from config import DB_PATH

_PASSWORDS = PasswordHasher()
_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class AuthStoreError(RuntimeError):
    """The local account store could not be used."""


class DuplicateAccountError(ValueError):
    """An account already exists for the normalized email address."""


def _connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    path = Path(db_path or DB_PATH)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), timeout=5)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as exc:
        raise AuthStoreError("Local account storage is unavailable.") from exc


def init_auth_store(db_path: str | Path | None = None) -> None:
    """Create the local account table without touching analysis data."""
    try:
        with _connect(db_path) as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS local_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )"""
            )
    except sqlite3.Error as exc:
        raise AuthStoreError("Local account storage is unavailable.") from exc


def validate_signup(name: str, email: str, password: str, confirmation: str) -> str:
    """Validate signup fields and return the normalized email."""
    clean_name = (name or "").strip()
    normalized_email = (email or "").strip().casefold()
    if not clean_name:
        raise ValueError("Enter your name.")
    if not _EMAIL.fullmatch(normalized_email):
        raise ValueError("Enter a valid email address.")
    if len(password or "") < 12:
        raise ValueError("Use a password with at least 12 characters.")
    if password != confirmation:
        raise ValueError("Passwords do not match.")
    return normalized_email


def create_user(name: str, email: str, password: str, confirmation: str,
                db_path: str | Path | None = None) -> dict:
    """Create a user, storing only an Argon2id hash."""
    normalized_email = validate_signup(name, email, password, confirmation)
    init_auth_store(db_path)
    try:
        with _connect(db_path) as conn:
            cursor = conn.execute(
                "INSERT INTO local_users (name, email, password_hash) VALUES (?, ?, ?)",
                (name.strip(), normalized_email, _PASSWORDS.hash(password)),
            )
            return {"id": cursor.lastrowid, "name": name.strip(), "email": normalized_email}
    except sqlite3.IntegrityError as exc:
        raise DuplicateAccountError("An account already exists for this email address.") from exc
    except sqlite3.Error as exc:
        raise AuthStoreError("Local account storage is unavailable.") from exc


def authenticate_user(email: str, password: str,
                      db_path: str | Path | None = None) -> dict | None:
    """Return safe session identity fields, or None for any invalid credentials."""
    init_auth_store(db_path)
    try:
        with _connect(db_path) as conn:
            row = conn.execute(
                "SELECT id, name, email, password_hash FROM local_users WHERE email = ?",
                ((email or "").strip().casefold(),),
            ).fetchone()
        if row is None:
            return None
        try:
            _PASSWORDS.verify(row["password_hash"], password or "")
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return None
        return {"id": row["id"], "name": row["name"], "email": row["email"]}
    except sqlite3.Error as exc:
        raise AuthStoreError("Local account storage is unavailable.") from exc


def get_user_by_id(user_id: int, db_path: str | Path | None = None) -> dict | None:
    """Revalidate a Streamlit session against the local account store."""
    init_auth_store(db_path)
    try:
        with _connect(db_path) as conn:
            row = conn.execute(
                "SELECT id, name, email FROM local_users WHERE id = ?", (user_id,)
            ).fetchone()
        return dict(row) if row else None
    except (sqlite3.Error, TypeError, ValueError) as exc:
        raise AuthStoreError("Local account storage is unavailable.") from exc


def set_authenticated_session(session_state, user: dict) -> None:
    """Store only non-secret identity fields in Streamlit's session state."""
    session_state["auth_user"] = {
        "id": user["id"], "name": user["name"], "email": user["email"]
    }


def clear_authenticated_session(session_state) -> None:
    """Clear all session and widget state, including password widget values."""
    session_state.clear()


def require_authenticated_user() -> bool:
    """Protect a Streamlit page and revalidate its local account session."""
    import streamlit as st

    identity = st.session_state.get("auth_user")
    if not isinstance(identity, dict) or not identity.get("id"):
        from src.ui_components import inject_global_css
        inject_global_css()
        st.warning("Sign in to access the TRACE//FIN investigation workspace.")
        st.page_link("app.py", label="Go to sign in", icon="🔐")
        return False
    try:
        current = get_user_by_id(identity["id"])
    except AuthStoreError:
        st.error("Local account storage is unavailable. Access is paused until it can be reached.")
        return False
    if current is None:
        clear_authenticated_session(st.session_state)
        st.warning("This account is no longer available. Please sign in again.")
        st.page_link("app.py", label="Go to sign in", icon="🔐")
        return False
    set_authenticated_session(st.session_state, current)
    return True


def password_hash_for_testing(email: str, db_path: str | Path | None = None) -> str | None:
    """Internal inspection helper for tests; never expose hashes in the UI."""
    init_auth_store(db_path)
    try:
        with _connect(db_path) as conn:
            row = conn.execute("SELECT password_hash FROM local_users WHERE email = ?",
                               (email.strip().casefold(),)).fetchone()
        return row[0] if row else None
    except sqlite3.Error as exc:
        raise AuthStoreError("Local account storage is unavailable.") from exc
