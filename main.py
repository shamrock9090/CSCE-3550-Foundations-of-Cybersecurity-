"""RESTful JWKS Server for CSCE 3550 — Project 3.

New in Project 3:
  - AES-256 encryption of private keys at rest (via NOT_MY_KEY env var)
  - POST /register  — user registration with Argon2-hashed passwords
  - Auth-request logging to the auth_logs table
  - Token-bucket rate limiter on POST /auth (10 req/s, 429 on breach)

SQL injection is prevented throughout by parameterized queries only.
"""

import os
import threading
import time
import uuid
from datetime import datetime, timezone

import jwt
from argon2 import PasswordHasher
from flask import Flask, request, jsonify

import db_manager
import key_manager

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Argon2 password hasher (configurable settings per spec)
# ---------------------------------------------------------------------------
_ph = PasswordHasher(
    time_cost=2,        # iterations
    memory_cost=65536,  # 64 MB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)

# ---------------------------------------------------------------------------
# Fixed-window rate limiter (10 requests/second on POST /auth)
# ---------------------------------------------------------------------------
_RATE_LIMIT = 10       # max requests per 1-second window
_RATE_WINDOW = 1.0     # window size in seconds
_bucket_lock = threading.Lock()
_buckets: dict[str, dict] = {}   # keyed by client IP


def _is_rate_limited(ip: str) -> bool:
    """Return True if the given IP has exceeded 10 requests per second.

    Uses a fixed-window counter: counts requests within the current
    1-second window and rejects once the count exceeds _RATE_LIMIT.
    """
    now = time.monotonic()
    with _bucket_lock:
        bucket = _buckets.get(ip)
        if bucket is None or (now - bucket["window_start"]) >= _RATE_WINDOW:
            # Start a fresh window
            _buckets[ip] = {"window_start": now, "count": 1}
            return False

        bucket["count"] += 1
        if bucket["count"] > _RATE_LIMIT:
            return True
        return False


# ---------------------------------------------------------------------------
# Database + key initialisation (runs once on module load)
# ---------------------------------------------------------------------------

def setup_database() -> None:
    """Initialize the SQLite DB tables and seed the initial RSA keys."""
    db_manager.initialize_db()
    key_manager.initialize_keys()


setup_database()


# ---------------------------------------------------------------------------
# JWKS endpoint
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
@app.route("/.well-known/jwks.json", methods=["GET"])
@app.route("/jwks", methods=["GET"])
def jwks():
    """Return non-expired public keys in JWKS format (RFC 7517)."""
    try:
        return jsonify(key_manager.get_jwks()), 200
    except Exception as err:
        return jsonify({"error": f"Failed to retrieve JWKS: {str(err)}"}), 500


# ---------------------------------------------------------------------------
# /auth endpoint — issue signed JWT + log the request
# ---------------------------------------------------------------------------

@app.route("/auth", methods=["POST"])
def auth():
    """Issue a signed RS256 JWT.

    Query params:
        expired: if present, sign with an expired key.

    Rate limited to 10 requests/second per IP (returns 429 on breach).
    Every successful request is logged to auth_logs.
    """
    client_ip = request.remote_addr or "127.0.0.1"

    # --- Rate limiting ---
    if _is_rate_limited(client_ip):
        return jsonify({"error": "Too Many Requests"}), 429

    # --- Determine whether to use an expired key ---
    expired_param = request.args.get("expired")
    is_expired = (
        expired_param is not None
        and expired_param.lower() in ("true", "1", "")
    )

    try:
        row = key_manager.get_key_for_auth(expired=is_expired)
    except ValueError as err:
        return jsonify({"error": str(err)}), 500

    kid, pem_bytes, exp_ts = row
    private_key = key_manager.deserialize_private_key(pem_bytes)

    now = datetime.now(timezone.utc)

    # Extract username from Basic Auth or JSON body (mock auth)
    username = "userABC"
    if request.authorization:
        username = request.authorization.username or username
    elif request.is_json:
        body = request.get_json(silent=True) or {}
        username = body.get("username", username)

    # Resolve user_id for auth_logs FK (None if user not in DB)
    user_row = db_manager.get_user_by_username(username)
    user_id = user_row[0] if user_row else None

    # --- Log the authentication request (before JWT encoding) ---
    db_manager.log_auth_request(client_ip, user_id)

    payload = {
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": exp_ts,
    }

    try:
        token = jwt.encode(
            payload,
            private_key,
            algorithm="RS256",
            headers={"kid": str(kid)},
        )
    except jwt.PyJWTError as err:
        return jsonify({"error": f"JWT encoding failed: {str(err)}"}), 500
    except Exception as err:
        return jsonify({"error": f"Internal server error: {str(err)}"}), 500

    return token, 200, {"Content-Type": "application/jwt"}


# ---------------------------------------------------------------------------
# /register endpoint
# ---------------------------------------------------------------------------

@app.route("/register", methods=["POST"])
def register():
    """Register a new user account.

    Accepts JSON body: {"username": "...", "email": "..."}
    Generates a UUIDv4 password, hashes it with Argon2, stores the user,
    and returns {"password": "<uuid>"}.
    """
    if not request.is_json:
        return jsonify({"error": "Request body must be JSON"}), 400

    body = request.get_json(silent=True) or {}
    username = body.get("username")
    email = body.get("email")

    if not username:
        return jsonify({"error": "username is required"}), 400

    # Generate a secure UUIDv4 password
    password = str(uuid.uuid4())

    # Hash with Argon2
    password_hash = _ph.hash(password)

    try:
        db_manager.create_user(username, password_hash, email)
    except Exception as err:
        # Covers UNIQUE constraint violations (duplicate username/email)
        return jsonify({"error": f"Registration failed: {str(err)}"}), 409

    return jsonify({"password": password}), 201


# ---------------------------------------------------------------------------
# Method Not Allowed handlers for REST compliance
# ---------------------------------------------------------------------------

UNSUPPORTED_JWKS = ["POST", "PUT", "DELETE", "PATCH"]
UNSUPPORTED_AUTH = ["GET", "PUT", "DELETE", "PATCH"]
UNSUPPORTED_REGISTER = ["GET", "PUT", "DELETE", "PATCH"]


@app.route("/.well-known/jwks.json", methods=UNSUPPORTED_JWKS)
@app.route("/jwks", methods=UNSUPPORTED_JWKS)
@app.route("/auth", methods=UNSUPPORTED_AUTH)
@app.route("/register", methods=UNSUPPORTED_REGISTER)
def method_not_allowed():
    """Return 405 Method Not Allowed for unsupported HTTP methods."""
    return jsonify({"error": "Method Not Allowed"}), 405


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
