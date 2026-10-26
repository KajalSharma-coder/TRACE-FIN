from pathlib import Path

import pytest

from src.auth import (
    AuthStoreError,
    DuplicateAccountError,
    authenticate_user,
    clear_authenticated_session,
    create_auth_session,
    create_user,
    get_user_by_id,
    get_user_by_auth_session,
    init_auth_store,
    password_hash_for_testing,
    revoke_auth_session,
    set_authenticated_session,
)


def test_signup_stores_argon2_hash_and_authenticates(tmp_path):
    db = tmp_path / "accounts.sqlite3"
    user = create_user("Analyst", "Analyst@Example.org", "correct horse battery staple", "correct horse battery staple", db)

    stored = password_hash_for_testing("analyst@example.org", db)
    assert stored.startswith("$argon2id$")
    assert "correct horse battery staple" not in stored
    assert authenticate_user("ANALYST@example.org", "correct horse battery staple", db) == user
    assert authenticate_user("analyst@example.org", "wrong password", db) is None
    assert authenticate_user("missing@example.org", "correct horse battery staple", db) is None


def test_signup_validation_and_duplicate_account(tmp_path):
    db = tmp_path / "accounts.sqlite3"
    with pytest.raises(ValueError, match="valid email"):
        create_user("Analyst", "not-an-email", "long enough password", "long enough password", db)
    with pytest.raises(ValueError, match="at least 12"):
        create_user("Analyst", "analyst@example.org", "short", "short", db)
    with pytest.raises(ValueError, match="do not match"):
        create_user("Analyst", "analyst@example.org", "long enough password", "different password", db)

    create_user("Analyst", "analyst@example.org", "long enough password", "long enough password", db)
    with pytest.raises(DuplicateAccountError):
        create_user("Second name", "ANALYST@example.org", "another long password", "another long password", db)


def test_session_contains_identity_only_and_logout_clears_everything():
    state = {"login_password": "temporary widget value", "analysis_result": {"risk_score": 80}}
    set_authenticated_session(state, {"id": 4, "name": "Analyst", "email": "a@example.org"})
    assert state["auth_user"] == {"id": 4, "name": "Analyst", "email": "a@example.org"}
    assert "password" not in repr(state["auth_user"]).lower()
    clear_authenticated_session(state)
    assert state == {}


def test_user_session_revalidation_and_missing_store_error(tmp_path):
    db = tmp_path / "accounts.sqlite3"
    user = create_user("Analyst", "analyst@example.org", "long enough password", "long enough password", db)
    assert get_user_by_id(user["id"], db) == user
    assert get_user_by_id(999, db) is None

    broken = tmp_path / "directory"
    broken.mkdir()
    (broken / "file").write_text("not a database")
    with pytest.raises(AuthStoreError):
        init_auth_store(broken / "file")


def test_auth_store_connections_close_deterministically(tmp_path):
    db = tmp_path / "accounts.sqlite3"

    init_auth_store(db)
    db.unlink()


def test_persistent_auth_token_is_hashed_validated_and_revocable(tmp_path):
    db = tmp_path / "accounts.sqlite3"
    user = create_user("Analyst", "analyst@example.org", "long enough password",
                       "long enough password", db)
    token = create_auth_session(user["id"], db)
    assert get_user_by_auth_session(token, db) == user
    assert get_user_by_auth_session("not-a-real-token", db) is None

    import sqlite3
    with sqlite3.connect(db) as conn:
        stored_tokens = [row[0] for row in conn.execute("SELECT token_hash FROM local_auth_sessions")]
    assert token not in stored_tokens
    assert len(stored_tokens) == 1

    revoke_auth_session(token, db)
    assert get_user_by_auth_session(token, db) is None


def test_public_homepage_and_login_route_are_available_without_auth():
    from streamlit.testing.v1 import AppTest

    project_root = Path(__file__).resolve().parents[1]
    app = AppTest.from_file(project_root / "app.py", default_timeout=10).run()
    assert any("See the risk." in (item.value or "") for item in app.markdown)
    assert any("ILLUSTRATIVE PREVIEW" in (item.value or "") or "LIVE WORKSPACE DATA" in (item.value or "")
               for item in app.markdown)
    assert not any("Overview dashboard" in (item.value or "") for item in app.title)

    app.query_params["auth"] = "login"
    app.run()
    assert any(item.value == "Welcome back" for item in app.subheader)


def test_protected_analysis_page_rejects_unauthenticated_session():
    from streamlit.testing.v1 import AppTest

    project_root = Path(__file__).resolve().parents[1]
    app = AppTest.from_file(project_root / "app.py", default_timeout=10).run()
    app.switch_page("pages/5_Batch_CSV_Analysis.py").run()
    assert any("Sign in to access" in (item.value or "") for item in app.warning)
    assert not any("Batch CSV Advertisement Analysis" in (item.value or "") for item in app.title)


def test_signup_login_shell_establishes_session_and_logout_clears_it(tmp_path, monkeypatch):
    from pathlib import Path
    from streamlit.testing.v1 import AppTest
    import src.auth as auth_module
    import src.database as database_module

    monkeypatch.setattr(auth_module, "DB_PATH", tmp_path / "accounts.sqlite3")
    monkeypatch.setattr(database_module, "DB_PATH", tmp_path / "records.sqlite3")
    monkeypatch.setattr(database_module, "get_database_url", lambda: None)
    database_module.reset_engine()
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    app = AppTest.from_file(app_path, default_timeout=10).run()
    app.query_params["auth"] = "signup"
    app.run()
    app.text_input(key="signup_name").set_value("Local Investigator")
    app.text_input(key="signup_email").set_value("local@example.org")
    app.text_input(key="signup_password").set_value("long enough password")
    app.text_input(key="signup_confirm").set_value("long enough password")
    app.button(key="signup_submit").click().run()

    assert app.session_state["auth_user"]["email"] == "local@example.org"
    assert any("Overview dashboard" in (item.value or "") for item in app.title)
    assert "signup_password" not in app.session_state
    assert "signup_confirm" not in app.session_state
    app.switch_page("pages/5_Batch_CSV_Analysis.py").run()
    assert any("Batch CSV Advertisement Analysis" in (item.value or "") for item in app.markdown)
    app.button(key="tracefin_logout").click().run()
    assert "auth_user" not in app.session_state
    assert "signup_password" not in app.session_state
    assert any("See the risk." in (item.value or "") for item in app.markdown)
