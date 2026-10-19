# Work 1: Secure REST API and CVE Analysis

A small notes API built with Flask, SQLite, PyJWT and bcrypt. It covers the API and
basic security part of the assignment. CI/CD, the Vulhub experiment and the final
report are still pending; this README will be extended with actual evidence.

## Run locally

Use Python 3.10 or newer. From the project directory:

```bash
# The work1 virtual environment already exists on this machine.
source work1/bin/activate
python -m pip install -r requirements-dev.txt
export JWT_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python -m flask --app app init-db --login alice
python -m flask --app app run --host 127.0.0.1 --port 5001
```

Choose a password when prompted (8–72 UTF-8 bytes); it is not echoed. The database
is saved in `instance/app.sqlite3`. Run `init-db` with a different login to add
another user; existing users and notes are kept. If the login already exists,
the command fails without changing its password.

Keep the server terminal open. Export the secret again before starting the app
in a new terminal. Generating a new secret invalidates previously issued tokens.
The server binds to localhost with debug mode off for this local lab.

## Endpoints and curl examples

| Method | Path | Authentication | Purpose |
| --- | --- | --- | --- |
| POST | `/auth/login` | None | Accept `login` and `password`; return a JWT |
| GET | `/api/data` | Bearer JWT | List the current user's notes |
| POST | `/api/data` | Bearer JWT | Create a note using a JSON `content` field |

In another terminal, replace `YOUR_PASSWORD` with the password you chose:

```bash
curl -i http://127.0.0.1:5001/api/data
# Expected: 401 (no token).

curl -sS http://127.0.0.1:5001/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"login":"alice","password":"YOUR_PASSWORD"}'
# Expected: access_token and expires_in=1800.
```

Copy the `access_token` value into `TOKEN` in that terminal:

```bash
TOKEN='PASTE_ACCESS_TOKEN_HERE'

curl -i http://127.0.0.1:5001/api/data \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"content":"My first secure note"}'
# Expected: 201, with the new note's id and content.

curl -i http://127.0.0.1:5001/api/data \
  -H "Authorization: Bearer $TOKEN"
# Expected: 200, with {"data":[...]} containing only this user's notes.
```

Invalid credentials/tokens return 401, invalid JSON/fields return 400, and bodies
over 16 KiB return 413. Notes must be non-blank and at most 1000 characters.

## Security measures

- **SQL injection:** every query containing user input uses SQLite `?` placeholders
  with a separate parameter tuple. No input is concatenated into SQL.
- **XSS:** note content is stored as text and escaped on output with MarkupSafe's
  `escape()`. Both note endpoints return JSON via `jsonify()`, with
  `Content-Type: application/json` and `X-Content-Type-Options: nosniff`.
  A future frontend should render text with `textContent`, rather than `innerHTML`.
- **Authentication:** passwords are stored only as salted bcrypt hashes (default
  cost 12). Login issues a 30-minute JWT. A shared decorator protects both note
  endpoints, fixes the allowed algorithm to HS256, requires `sub`/`iat`/`exp`,
  checks the signature and expiry, and checks that the user still exists.
- **Configuration and access:** the JWT signing secret comes from an environment
  variable (at least 32 bytes), with no default secret. Database queries restrict
  notes to the authenticated user's ID. Secrets, the local database, the virtual
  environment and the upstream Vulhub checkout are excluded from Git.

References: [OWASP SQL injection prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html),
[Flask security](https://flask.palletsprojects.com/en/stable/web-security/),
[PyJWT usage](https://pyjwt.readthedocs.io/en/stable/usage.html).

## Local checks

```bash
python -m pytest -q
mkdir -p reports
python -m bandit app.py -f json -o reports/bandit.json
```

Tests use temporary databases, so they do not change your local notes. They cover
login, password hashing, both protected endpoints, invalid/expired/forged tokens,
SQL injection inputs, XSS escaping, user isolation and invalid input.
Bandit is SAST; it does not replace a dependency vulnerability scanner (SCA).

Local verification on 2026-10-19: **30 tests passed**, **0 Bandit findings**
(no checks suppressed), and **6 real curl checks passed**, including login,
authenticated create/read, missing/invalid tokens and escaped script content.
Local reports are `reports/pytest.xml`, `reports/bandit.json` and
`reports/http-check.txt`. These are local results; CI screenshots are still pending.

## Assignment progress

| Requirement from the assignment | Status |
| --- | --- |
| Choose stack and initialize local Git | Implemented locally |
| Login + protected data + a third method | Implemented |
| Parameterized SQL, XSS escaping, JWT and password hashing | Implemented |
| API tests and curl instructions | Implemented locally |
| Public remote repository | Pending upload |
| CI on push/PR with SAST and SCA, reports/screenshots | Pending |
| Select and launch a Vulhub CVE | Pending |
| Reproduce, explain root cause, apply and verify fix | Pending |
| CVE evidence, fix folder, successful CI link, final report | Pending |

The final report must include the required title page (work number/title,
variant, surname/name and HDU number). Real CI/CVE results and screenshots will
be added after those steps run successfully.
