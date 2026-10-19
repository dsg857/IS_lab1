import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
import pytest

from app import create_app


@pytest.fixture
def app(tmp_path):
    application = create_app({
        "TESTING": True,
        "DATABASE": tmp_path / "test.sqlite3",
        "JWT_SECRET_KEY": secrets.token_hex(32),
    })
    result = application.test_cli_runner().invoke(
        args=["init-db", "--login", "alice"], input="study-password\nstudy-password\n",
    )
    assert result.exit_code == 0, result.output
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def login_headers(client, username="alice"):
    response = client.post("/auth/login", json={"login": username, "password": "study-password"})
    assert response.status_code == 200
    return {"Authorization": "Bearer " + response.json["access_token"]}


def test_login_and_password_storage(app, client):
    headers = login_headers(client)
    token = headers["Authorization"].split()[1]
    claims = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
    assert claims["sub"] == "alice"
    assert claims["exp"] - claims["iat"] == 1800
    with sqlite3.connect(app.config["DATABASE"]) as db:
        hashed = db.execute("SELECT password_hash FROM users").fetchone()[0]
    assert hashed != b"study-password"
    assert bcrypt.checkpw(b"study-password", hashed)


@pytest.mark.parametrize("username,password", [
    ("alice", "wrong-password"),
    ("unknown", "study-password"),
    ("alice' OR '1'='1' --", "study-password"),
])
def test_wrong_credentials_and_sql_injection(client, username, password):
    assert client.post("/auth/login", json={"login": username, "password": password}).status_code == 401


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize("kind", ["missing", "malformed", "expired", "forged", "missing-exp", "wrong-algorithm"])
def test_protected_endpoints_reject_bad_tokens(app, client, method, kind):
    now = datetime.now(timezone.utc)
    claims = {"sub": "alice", "iat": now, "exp": now + timedelta(minutes=1)}
    headers = {}
    if kind == "malformed":
        headers = {"Authorization": "Bearer invalid-token"}
    elif kind != "missing":
        if kind == "expired":
            claims["exp"] = now - timedelta(minutes=1)
        if kind == "missing-exp":
            del claims["exp"]
        key = secrets.token_hex(32) if kind == "forged" else app.config["JWT_SECRET_KEY"]
        token = jwt.encode(claims, key, algorithm="HS384" if kind == "wrong-algorithm" else "HS256")
        headers = {"Authorization": "Bearer " + token}
    response = client.open("/api/data", method=method, headers=headers, json={"content": "test"})
    assert response.status_code == 401


def test_create_read_escape_and_sql_safety(client):
    headers = login_headers(client)
    content = "<script>alert('xss')</script>'; DROP TABLE notes; --"
    response = client.post("/api/data", headers=headers, json={"content": content})
    assert response.status_code == 201
    assert "<script>" not in response.json["content"]
    assert "&lt;script&gt;" in response.json["content"]
    assert "DROP TABLE notes" in response.json["content"]
    rows = client.get("/api/data", headers=headers)
    assert rows.json["data"] == [response.json]
    assert rows.mimetype == "application/json"
    assert rows.headers["X-Content-Type-Options"] == "nosniff"
    assert rows.headers["Cache-Control"] == "no-store"
    assert client.post("/api/data", headers=headers, json={"content": "still works"}).status_code == 201


def test_users_only_see_their_own_notes(app, client):
    alice = login_headers(client)
    assert client.post("/api/data", headers=alice, json={"content": "private"}).status_code == 201
    result = app.test_cli_runner().invoke(
        args=["init-db", "--login", "bob"], input="study-password\nstudy-password\n",
    )
    assert result.exit_code == 0
    bob = login_headers(client, "bob")
    assert client.get("/api/data", headers=bob).json == {"data": []}
    assert len(client.get("/api/data", headers=alice).json["data"]) == 1


@pytest.mark.parametrize("body", [[], None, {"login": 123, "password": "x"},
                                      {"login": "alice", "password": "密" * 25}])
def test_invalid_login_input(client, body):
    assert client.post("/auth/login", json=body).status_code == 400


@pytest.mark.parametrize("body", [[], {}, {"content": " "}, {"content": 123}, {"content": "x" * 1001}])
def test_invalid_note_input(client, body):
    assert client.post("/api/data", headers=login_headers(client), json=body).status_code == 400


def test_oversized_request(client):
    response = client.post("/api/data", headers=login_headers(client), json={"content": "x" * 17000})
    assert response.status_code == 413


def test_missing_secret_fails_closed(monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError, match="JWT_SECRET_KEY"):
        create_app()


def test_duplicate_user_does_not_reset_password(app, client):
    result = app.test_cli_runner().invoke(
        args=["init-db", "--login", "alice"], input="different-password\ndifferent-password\n",
    )
    assert result.exit_code != 0
    assert "already exists" in result.output
    assert client.get("/api/data", headers=login_headers(client)).status_code == 200
