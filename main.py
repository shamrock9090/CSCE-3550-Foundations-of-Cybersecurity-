"""RESTful JWKS Server for CSCE 3550 — Project 2.

Provides a JWKS endpoint for public key discovery and a /auth endpoint
for issuing signed JWTs. Private keys are persisted in a SQLite database
(totally_not_my_privateKeys.db) and SQL injection is prevented throughout
by using parameterized queries exclusively.
"""

import os
from datetime import datetime, timezone

import jwt
from flask import Flask, request, jsonify

import db_manager
import key_manager

app = Flask(__name__)


def setup_database() -> None:
    """Initialize the SQLite DB and populate it with initial RSA keys."""
    db_manager.initialize_db()
    key_manager.initialize_keys()


# Run DB setup once when the module is loaded (covers both `flask run`
# and `python main.py` invocations, as well as test imports).
setup_database()


@app.route("/", methods=["GET"])
@app.route("/.well-known/jwks.json", methods=["GET"])
@app.route("/jwks", methods=["GET"])
def jwks():
    """JWKS endpoint returning non-expired public keys per RFC 7517."""
    try:
        return jsonify(key_manager.get_jwks()), 200
    except Exception as err:
        return jsonify({"error": f"Failed to retrieve JWKS: {str(err)}"}), 500


@app.route("/auth", methods=["POST"])
def auth():
    """Authentication endpoint issuing signed JWTs.

    Accepts HTTP Basic Auth or a JSON body with 'username'/'password'.
    The ?expired query parameter forces signing with an expired key.
    """
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

    # Deserialize the private key from PEM bytes stored in the DB
    private_key = key_manager.deserialize_private_key(pem_bytes)

    now = datetime.now(timezone.utc)

    # Extract username from Basic Auth or JSON body (mock auth only)
    username = "userABC"
    if request.authorization:
        username = request.authorization.username or username
    elif request.is_json:
        body = request.get_json(silent=True) or {}
        username = body.get("username", username)

    payload = {
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": exp_ts,
    }

    headers = {
        "kid": str(kid),
    }

    try:
        token = jwt.encode(
            payload,
            private_key,
            algorithm="RS256",
            headers=headers,
        )
    except jwt.PyJWTError as err:
        return jsonify({"error": f"JWT encoding failed: {str(err)}"}), 500
    except Exception as err:
        return jsonify({"error": f"Internal server error: {str(err)}"}), 500

    return token, 200, {"Content-Type": "application/jwt"}


# Method Not Allowed handlers for REST compliance
UNSUPPORTED_JWKS = ["POST", "PUT", "DELETE", "PATCH"]
UNSUPPORTED_AUTH = ["GET", "PUT", "DELETE", "PATCH"]


@app.route("/.well-known/jwks.json", methods=UNSUPPORTED_JWKS)
@app.route("/jwks", methods=UNSUPPORTED_JWKS)
@app.route("/auth", methods=UNSUPPORTED_AUTH)
def method_not_allowed():
    """Return HTTP 405 Method Not Allowed for unsupported methods."""
    return jsonify({"error": "Method Not Allowed"}), 405


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
