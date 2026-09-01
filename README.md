# CSCE 3550 - RESTful JWKS Server

This repository contains the CSCE 3550 Foundations of Cybersecurity project implementing a RESTful JWKS (JSON Web Key Set) server in Python using Flask, `cryptography`, and `PyJWT`.

## Features
- **RSA Key Generation**: Generates 2048-bit RSA key pairs with unique Key IDs (`kid`) and expiry timestamps.
- **JWKS Endpoint (`GET /.well-known/jwks.json` & `GET /jwks`)**: Exposes active, non-expired public keys formatted in JWKS format per RFC 7517.
- **Authentication Endpoint (`POST /auth`)**: Returns signed JWTs (`RS256`). Supports an `expired` query parameter (`/auth?expired=true`) to return tokens signed with an expired key.
- **RESTful Compliance**: Enforces proper HTTP status codes, including HTTP 405 Method Not Allowed for unsupported request methods.

## Prerequisites
- Python 3.10+
- Virtual environment (`venv`)

## Setup & Installation
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Running the Server
```bash
python3 main.py
```
The server runs on `http://localhost:8080` by default.

## Endpoints
- `GET /.well-known/jwks.json` or `GET /jwks`: Returns valid public keys in JWKS format.
- `POST /auth`: Returns a valid, unexpired signed JWT.
- `POST /auth?expired=true`: Returns a JWT signed with an expired key.

## Running Tests & Coverage
```bash
pytest --cov=. --cov-report=term-missing
```

## Linting
```bash
flake8 key_manager.py main.py test_app.py
```
