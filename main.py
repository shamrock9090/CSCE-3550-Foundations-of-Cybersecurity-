"""RESTful JWKS Server for CSCE 3550.

Provides a JWKS endpoint for public key discovery and a /auth endpoint
for issuing signed JWTs.
"""

import os
from datetime import datetime, timezone
import jwt
from flask import Flask, request, jsonify
from key_manager import KeyManager

app = Flask(__name__)
key_manager = KeyManager()


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
    """Authentication endpoint issuing signed JWTs."""
    expired_param = request.args.get("expired")
    is_expired = (
        expired_param is not None
        and expired_param.lower() in ("true", "1", "")
    )

    try:
        key_entry = key_manager.get_key(expired=is_expired)
    except ValueError as err:
        return jsonify({"error": str(err)}), 500

    now = datetime.now(timezone.utc)
    exp_time = int(key_entry.expiry.timestamp())

    payload = {
        "sub": "mock-user-123",
        "iat": int(now.timestamp()),
        "exp": exp_time,
    }

    headers = {
        "kid": key_entry.kid,
    }

    try:
        token = jwt.encode(
            payload,
            key_entry.private_key,
            algorithm="RS256",
            headers=headers,
        )
    except jwt.PyJWTError as err:
        return jsonify({"error": f"JWT encoding failed: {str(err)}"}), 500
    except Exception as err:
        return jsonify({"error": f"Internal server error: {str(err)}"}), 500

    return token, 200, {"Content-Type": "application/jwt"}


# Method Not Allowed Handlers for REST compliance
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
