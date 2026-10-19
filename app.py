"""A small, authenticated notes API for Work 1."""

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import bcrypt
import click
import jwt
from flask import Flask, g, jsonify, request
from markupsafe import escape


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        DATABASE=Path(app.instance_path) / "app.sqlite3",
        JWT_SECRET_KEY=os.environ.get("JWT_SECRET_KEY"),
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    secret = app.config["JWT_SECRET_KEY"]
    if not isinstance(secret, str) or len(secret.encode("utf-8")) < 32:
        raise RuntimeError("Set JWT_SECRET_KEY to a random secret of at least 32 bytes.")
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    @app.teardown_appcontext
    def close_db(error=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.cli.command("init-db")
    @click.option("--login", prompt=True)
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
    def init_db(login, password):
        """Create the tables and add one user, without deleting existing data."""
        if not login.strip() or len(login) > 64:
            raise click.ClickException("Login must contain 1 to 64 characters.")
        if not 8 <= len(password.encode("utf-8")) <= 72:
            raise click.ClickException("Password must contain 8 to 72 UTF-8 bytes.")
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                login TEXT NOT NULL UNIQUE,
                password_hash BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                content TEXT NOT NULL
            );
        """)
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        try:
            db.execute(
                "INSERT INTO users (login, password_hash) VALUES (?, ?)",
                (login, password_hash),
            )
            db.commit()
        except sqlite3.IntegrityError as error:
            raise click.ClickException("This login already exists.") from error
        click.echo("Database ready; user created.")

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            auth = request.headers.get("Authorization", "").split()
            if len(auth) != 2 or auth[0].lower() != "bearer":
                return jsonify(error="A Bearer token is required."), 401
            try:
                claims = jwt.decode(
                    auth[1], secret, algorithms=["HS256"],
                    options={"require": ["sub", "exp", "iat"]},
                )
            except jwt.InvalidTokenError:
                return jsonify(error="Invalid or expired token."), 401
            user = get_db().execute(
                "SELECT id FROM users WHERE login = ?", (claims["sub"],)
            ).fetchone()
            if user is None:
                return jsonify(error="Invalid or expired token."), 401
            g.user_id = user["id"]
            return view(*args, **kwargs)
        return wrapped

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/auth/login")
    def login():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(error="Send a JSON object."), 400
        username, password = body.get("login"), body.get("password")
        if (not isinstance(username, str) or not 1 <= len(username) <= 64
                or not isinstance(password, str)
                or not 1 <= len(password.encode("utf-8")) <= 72):
            return jsonify(error="Invalid login or password format."), 400
        user = get_db().execute(
            "SELECT login, password_hash FROM users WHERE login = ?", (username,)
        ).fetchone()
        if user is None or not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"]):
            return jsonify(error="Invalid login or password."), 401
        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {"sub": user["login"], "iat": now, "exp": now + timedelta(minutes=30)},
            secret, algorithm="HS256",
        )
        return jsonify(access_token=token, expires_in=1800)

    @app.get("/api/data")
    @login_required
    def get_data():
        rows = get_db().execute(
            "SELECT id, content FROM notes WHERE user_id = ? ORDER BY id", (g.user_id,)
        ).fetchall()
        return jsonify(data=[{"id": row["id"], "content": str(escape(row["content"]))}
                             for row in rows])

    @app.post("/api/data")
    @login_required
    def create_data():
        body = request.get_json(silent=True)
        content = body.get("content") if isinstance(body, dict) else None
        if not isinstance(content, str) or not content.strip() or len(content) > 1000:
            return jsonify(error="Content must contain 1 to 1000 non-blank characters."), 400
        db = get_db()
        result = db.execute(
            "INSERT INTO notes (user_id, content) VALUES (?, ?)", (g.user_id, content)
        )
        db.commit()
        return jsonify(id=result.lastrowid, content=str(escape(content))), 201

    return app
