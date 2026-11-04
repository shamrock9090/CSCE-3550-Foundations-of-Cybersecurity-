"""RESTful JWKS Server for CSCE 3550 — Project 2.

Extends the basic JWKS server with SQLite database persistence
(totally_not_my_privateKeys.db) for storing RSA private keys.
All SQL queries use parameterized placeholders (?) to guarantee protection
against SQL injection vulnerabilities.
"""

import base64
import os
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request

# ---------------------------------------------------------------------------
# Configuration & Constants
# ---------------------------------------------------------------------------
DB_FILE: str = "totally_not_my_privateKeys.db"

CREATE_TABLE_SQL: str = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
"""

app = Flask(__name__)


# ---------------------------------------------------------------------------
# SQLite Database Helpers (All Parameterized)
# ---------------------------------------------------------------------------
def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Open and return a new SQLite database connection.

    Args:
        db_path: Path to database file. Defaults to DB_FILE.

    Returns:
        A sqlite3.Connection instance with row factory configured.
    """
    path = db_path if db_path is not None else DB_FILE
    conn = sqlite3.connect(path)
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """Create the SQLite database and keys table if they do not exist.

    Args:
        db_path: Path to database file. Defaults to DB_FILE.

    Raises:
        sqlite3.Error: If a database error occurs during table creation.
    """
    conn = get_db_connection(db_path)
    try:
        conn.execute(CREATE_TABLE_SQL)
        conn.commit()
    except sqlite3.Error as err:
        conn.rollback()
        raise sqlite3.Error(
            f"Database initialization error: {err}"
        ) from err
    finally:
        conn.close()


def save_key(
    pem_bytes: bytes, exp_timestamp: int, db_path: Optional[str] = None
) -> int:
    """Insert a serialized private key and expiry into the keys table.

    Uses a parameterized query to prevent SQL injection.

    Args:
        pem_bytes: PKCS1 PEM bytes of the private key.
        exp_timestamp: Unix epoch timestamp when key expires.
        db_path: Optional custom database file path.

    Returns:
        The auto-generated kid (integer primary key).

    Raises:
        sqlite3.Error: If inserting the key into the database fails.
    """
    sql = "INSERT INTO keys (key, exp) VALUES (?, ?)"
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(sql, (pem_bytes, exp_timestamp))
        conn.commit()
        return cursor.lastrowid
    except sqlite3.Error as err:
        conn.rollback()
        raise sqlite3.Error(f"Failed to persist key: {err}") from err
    finally:
        conn.close()


def get_unexpired_key(
    db_path: Optional[str] = None,
) -> Optional[Tuple[int, bytes, int]]:
    """Retrieve one non-expired private key row from the database.

    Uses a parameterized query (exp > ?).

    Args:
        db_path: Optional custom database file path.

    Returns:
        A (kid, key, exp) tuple if found, otherwise None.

    Raises:
        sqlite3.Error: If query execution fails.
    """
    now_ts = int(datetime.now(timezone.utc).timestamp())
    sql = "SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1"
    conn = get_db_connection(db_path)
    try:
        row = conn.execute(sql, (now_ts,)).fetchone()
        return row
    except sqlite3.Error as err:
        raise sqlite3.Error(
            f"Error querying unexpired key: {err}"
        ) from err
    finally:
        conn.close()


def get_expired_key(
    db_path: Optional[str] = None,
) -> Optional[Tuple[int, bytes, int]]:
    """Retrieve one expired private key row from the database.

    Uses a parameterized query (exp <= ?).

    Args:
        db_path: Optional custom database file path.

    Returns:
        A (kid, key, exp) tuple if found, otherwise None.

    Raises:
        sqlite3.Error: If query execution fails.
    """
    now_ts = int(datetime.now(timezone.utc).timestamp())
    sql = "SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1"
    conn = get_db_connection(db_path)
    try:
        row = conn.execute(sql, (now_ts,)).fetchone()
        return row
    except sqlite3.Error as err:
        raise sqlite3.Error(f"Error querying expired key: {err}") from err
    finally:
        conn.close()


def get_all_valid_keys(
    db_path: Optional[str] = None,
) -> List[Tuple[int, bytes, int]]:
    """Retrieve all non-expired private key rows from the database.

    Uses a parameterized query (exp > ?).

    Args:
        db_path: Optional custom database file path.

    Returns:
        A list of (kid, key, exp) tuples.

    Raises:
        sqlite3.Error: If query execution fails.
    """
    now_ts = int(datetime.now(timezone.utc).timestamp())
    sql = "SELECT kid, key, exp FROM keys WHERE exp > ?"
    conn = get_db_connection(db_path)
    try:
        rows = conn.execute(sql, (now_ts,)).fetchall()
        return rows
    except sqlite3.Error as err:
        raise sqlite3.Error(
            f"Error querying all valid keys: {err}"
        ) from err
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Cryptographic & JWK Helpers
# ---------------------------------------------------------------------------
def int_to_base64url(val: int) -> str:
    """Encode an integer as a base64url string without padding (RFC 7515).

    Args:
        val: The integer value to encode (e.g. RSA modulus or exponent).

    Returns:
        Base64url-encoded string.
    """
    byte_length = max(1, (val.bit_length() + 7) // 8)
    val_bytes = val.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(val_bytes).rstrip(b"=").decode("utf-8")


def serialize_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialize an RSA private key to PKCS1 PEM bytes.

    Args:
        private_key: The RSA private key instance.

    Returns:
        PEM bytes formatted according to PKCS1.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_private_key(pem_bytes: bytes) -> rsa.RSAPrivateKey:
    """Deserialize PEM bytes from the database into an RSA private key.

    Args:
        pem_bytes: PKCS1 or PKCS8 PEM-encoded private key bytes.

    Returns:
        RSAPrivateKey instance.
    """
    return serialization.load_pem_private_key(pem_bytes, password=None)


def generate_and_store_key(
    expiry: datetime, key_size: int = 2048, db_path: Optional[str] = None
) -> int:
    """Generate a new RSA key pair and persist the private key to the DB.

    Args:
        expiry: UTC datetime indicating expiration.
        key_size: RSA key length in bits (default 2048).
        db_path: Optional custom database file path.

    Returns:
        The auto-generated kid for the new database row.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    pem_bytes = serialize_private_key(private_key)
    exp_ts = int(expiry.timestamp())
    return save_key(pem_bytes, exp_ts, db_path=db_path)


def key_row_to_jwk(row: Tuple[int, bytes, int]) -> Dict[str, Any]:
    """Convert a database key row into a JWK dictionary (RFC 7517).

    Args:
        row: A (kid, key_bytes, exp) database tuple.

    Returns:
        A dictionary formatted as a JWK.
    """
    kid, pem_bytes, _ = row
    private_key = deserialize_private_key(pem_bytes)
    public_numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": str(kid),
        "n": int_to_base64url(public_numbers.n),
        "e": int_to_base64url(public_numbers.e),
    }


def get_jwks(db_path: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
    """Retrieve all non-expired keys and build the JWKS response structure.

    Args:
        db_path: Optional custom database file path.

    Returns:
        Dict with "keys" list per RFC 7517.
    """
    rows = get_all_valid_keys(db_path=db_path)
    return {"keys": [key_row_to_jwk(row) for row in rows]}


def seed_initial_keys(db_path: Optional[str] = None) -> None:
    """Ensure the database contains at least one valid and one expired key.

    Generates:
      - 1 key expiring in 1 hour (valid)
      - 1 key expired 1 hour ago (expired)

    Args:
        db_path: Optional custom database file path.
    """
    now = datetime.now(timezone.utc)
    if get_unexpired_key(db_path=db_path) is None:
        generate_and_store_key(
            now + timedelta(hours=1), key_size=2048, db_path=db_path
        )
    if get_expired_key(db_path=db_path) is None:
        generate_and_store_key(
            now - timedelta(hours=1), key_size=2048, db_path=db_path
        )


# ---------------------------------------------------------------------------
# Flask HTTP Endpoints
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
@app.route("/.well-known/jwks.json", methods=["GET"])
@app.route("/jwks", methods=["GET"])
def jwks_endpoint() -> Any:
    """Return all valid (non-expired) public keys in JWKS format.

    Returns:
        JSON response with the list of active public JWKs.
    """
    try:
        data = get_jwks()
        return jsonify(data), 200
    except sqlite3.Error as err:
        return jsonify(
            {"error": f"Database error retrieving JWKS: {str(err)}"}
        ), 500
    except Exception as err:
        return jsonify({"error": f"Failed to retrieve JWKS: {str(err)}"}), 500


@app.route("/auth", methods=["POST"])
def auth_endpoint() -> Any:
    """Issue a signed JWT using a private key from the SQLite database.

    Accepts mock authentication via HTTP Basic Auth or JSON body.
    If the 'expired' query parameter is present, signs with an expired key.

    Returns:
        Encoded RS256 JWT string with 200 status code, or JSON error with 500.
    """
    expired_param = request.args.get("expired")
    is_expired = expired_param is not None and (
        expired_param.lower() in ("true", "1", "") or expired_param == ""
    )

    try:
        row = (
            get_expired_key()
            if is_expired
            else get_unexpired_key()
        )
    except sqlite3.Error as err:
        return jsonify({"error": f"Database error: {str(err)}"}), 500

    if row is None:
        label = "expired" if is_expired else "unexpired"
        return jsonify({"error": f"No {label} key found in database"}), 500

    kid, pem_bytes, exp_ts = row

    try:
        private_key = deserialize_private_key(pem_bytes)
    except Exception as err:
        return jsonify(
            {"error": f"Key deserialization failed: {str(err)}"}
        ), 500

    # Mock user authentication extraction
    username = "userABC"
    if request.authorization and request.authorization.username:
        username = request.authorization.username
    elif request.is_json:
        body = request.get_json(silent=True) or {}
        username = body.get("username", username)

    now = datetime.now(timezone.utc)
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


UNSUPPORTED_JWKS = ["POST", "PUT", "DELETE", "PATCH"]
UNSUPPORTED_AUTH = ["GET", "PUT", "DELETE", "PATCH"]


# Method Not Allowed handlers for strict REST compliance
@app.route("/.well-known/jwks.json", methods=UNSUPPORTED_JWKS)
@app.route("/jwks", methods=UNSUPPORTED_JWKS)
@app.route("/auth", methods=UNSUPPORTED_AUTH)
def method_not_allowed() -> Any:
    """Return HTTP 405 Method Not Allowed for unsupported HTTP verbs.

    Returns:
        JSON error response with HTTP 405 status code.
    """
    return jsonify({"error": "Method Not Allowed"}), 405


# ---------------------------------------------------------------------------
# Server Startup
# ---------------------------------------------------------------------------
def setup_app(db_path: Optional[str] = None) -> None:
    """Initialize SQLite database and seed keys on application startup."""
    init_db(db_path)
    seed_initial_keys(db_path)


# Ensure DB exists and has initial keys upon module load
setup_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
