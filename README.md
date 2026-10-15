[Pasted 2026-10-15 at 4.59.04 PM.tiff](https://github.com/user-attachments/files/33517335/Pasted.2026-10-15.at.4.59.04.PM.png)
[Pasted 2026-10-15 at 5.03.18 PM.tiff](https://github.com/user-attachments/files/33517337/Pasted.2026-10-15.at.5.03.18.PM.png)

# CSCE 3550 — Project 2: JWKS Server with SQLite

A RESTful JWKS (JSON Web Key Set) server built with Python/Flask, backed by a SQLite database for persistent private key storage. Parameterized SQL queries are used throughout to prevent SQL injection.

## Features

- **SQLite persistence**: RSA private keys are stored in `totally_not_my_privateKeys.db`
- **SQL injection prevention**: All DB queries use parameterized placeholders (`?`)
- **Key serialization**: Keys are stored as PKCS8 PEM-encoded blobs and deserialized on read
- **`GET /.well-known/jwks.json`** — Returns all valid (non-expired) public keys in JWKS format
- **`POST /auth`** — Issues a signed RS256 JWT; use `?expired=true` for a JWT signed with an expired key
- Accepts **HTTP Basic Auth** and **JSON body** (`{"username": ..., "password": ...}`)
- Method Not Allowed (405) for unsupported HTTP methods on each route

## Database Schema

```sql
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
```

## Project Structure

| File | Purpose |
|------|---------|
| `main.py` | Flask app, route handlers, DB initialization |
| `key_manager.py` | RSA key generation, serialization, JWKS formatting |
| `db_manager.py` | SQLite CRUD with parameterized queries |
| `test_app.py` | 42 unit + integration tests (99% coverage) |

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install flask pyjwt cryptography pytest pytest-cov flake8
```

## Running the Server

```bash
# The DB file is created automatically on startup
python main.py
# Server runs on http://0.0.0.0:8080
```

## Running Tests

```bash
venv/bin/pytest test_app.py --cov=. --cov-report=term-missing -v
```

## Linting

```bash
venv/bin/flake8 main.py key_manager.py db_manager.py --max-line-length=100
```

## Blackbox Testing (Gradebot)

Download the [test client](https://github.com/jh125486/CSCE3550/releases) and run:

```bash
# Ensure the server is running first (python main.py)
./gradebot project2
```

The DB file (`totally_not_my_privateKeys.db`) must be in the current directory.
