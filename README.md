# CSCE 3550 - RESTful JWKS Server
#<img width="3024" height="1964" alt="Image 9-7-26 at 11 59 AM" src="https://github.com/user-attachments/assets/74606917-9cb8-4992-b1d8-8e1771216d88" />
#<img width="3024" height="1964" alt="Image 9-7-26 at 12 02 PM" src="https://github.com/user-attachments/assets/5d58c30f-8deb-4366-8903-30b5be788ce8" />

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
