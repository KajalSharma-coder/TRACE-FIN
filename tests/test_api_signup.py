import pytest
from fastapi.testclient import TestClient

import src.auth as auth_module
from backend.api.main import app


@pytest.fixture
def signup_client(tmp_path, monkeypatch):
    monkeypatch.setattr(auth_module, "DB_PATH", tmp_path / "accounts.sqlite3")
    monkeypatch.setenv("TRACEFIN_AUTH_COOKIE_SECURE", "false")
    monkeypatch.setenv("TRACEFIN_PUBLIC_SIGNUP_ENABLED", "true")
    return TestClient(app)


def csrf_for(client: TestClient) -> str:
    response = client.get("/api/auth/csrf")
    assert response.status_code == 200
    return response.json()["csrf_token"]


def registration_payload(**overrides):
    payload = {
        "name": "New Analyst",
        "email": "new.analyst@example.org",
        "password": "a sufficiently long password",
        "confirmation": "a sufficiently long password",
    }
    payload.update(overrides)
    return payload


def register(client: TestClient, **overrides):
    token = csrf_for(client)
    return client.post(
        "/api/auth/register",
        headers={"X-CSRF-Token": token},
        json=registration_payload(**overrides),
    )


def test_registration_creates_session_without_exposing_secrets(signup_client):
    response = register(signup_client)
    assert response.status_code == 201
    assert response.json()["user"] == {
        "id": 1,
        "name": "New Analyst",
        "email": "new.analyst@example.org",
    }
    assert "password" not in response.text
    assert "password_hash" not in response.text
    assert "httponly" in response.headers["set-cookie"].lower()
    session = signup_client.get("/api/auth/session")
    assert session.status_code == 200
    assert session.json()["user"]["email"] == "new.analyst@example.org"


def test_registration_rejects_duplicate_email(signup_client):
    assert register(signup_client).status_code == 201
    duplicate = register(signup_client, email=" NEW.ANALYST@example.org ")
    assert duplicate.status_code == 409
    assert duplicate.json() == {"detail": "An account already exists for this email address."}


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"email": "not-an-email"}, "Enter a valid email address."),
        ({"password": "short", "confirmation": "short"}, "Use a password with at least 12 characters."),
        ({"confirmation": "different sufficiently long password"}, "Passwords do not match."),
        ({"name": ""}, "Enter your name."),
    ],
)
def test_registration_validates_fields_on_backend(signup_client, overrides, message):
    response = register(signup_client, **overrides)
    assert response.status_code == 422
    assert response.json() == {"detail": message}


def test_registration_rejects_missing_fields(signup_client):
    token = csrf_for(signup_client)
    response = signup_client.post(
        "/api/auth/register",
        headers={"X-CSRF-Token": token},
        json={"email": "missing@example.org"},
    )
    assert response.status_code == 422


def test_registration_requires_csrf(signup_client):
    csrf_for(signup_client)
    response = signup_client.post("/api/auth/register", json=registration_payload())
    assert response.status_code == 403
    assert response.json() == {"detail": "CSRF validation failed."}


def test_registration_can_be_disabled_explicitly(signup_client, monkeypatch):
    monkeypatch.setenv("TRACEFIN_PUBLIC_SIGNUP_ENABLED", "false")
    response = register(signup_client)
    assert response.status_code == 403
    assert response.json() == {"detail": "Public registration is disabled."}


def test_registered_password_is_used_by_existing_login_flow(signup_client):
    assert register(signup_client).status_code == 201
    signup_client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_for(signup_client)})
    response = signup_client.post(
        "/api/auth/login",
        headers={"X-CSRF-Token": csrf_for(signup_client)},
        json={"email": "new.analyst@example.org", "password": "wrong password"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password."}
