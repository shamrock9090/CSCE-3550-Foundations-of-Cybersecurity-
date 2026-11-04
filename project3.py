"""RESTful JWKS Server for CSCE 3550 — Project 3.

Features implemented:
  - Symmetric AES-256-CBC encryption of RSA private keys at rest (NOT_MY_KEY).
  - User registration (POST /register) with UUIDv4 passwords and Argon2.
  - Authentication request logging to the auth_logs table.
  - Sliding-window rate limiter on POST /auth (10 req/s, returns HTTP 429).
  - Public JWKS endpoint (GET /.well-known/jwks.json) and JWT issuance.
  - Parameterized SQLite queries throughout to eliminate SQL injection risks.
"""

import base64
import collections
import hashlib
import os
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

import jwt
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, jsonify, request

# ---------------------------------------------------------------------------
# Configuration & Constants
# ---------------------------------------------------------------------------
DB_FILE: str = "totally_not_my_privateKeys.db"

CREATE_KEYS_TABLE: str = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
"""

CREATE_USERS_TABLE: str = """
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
)
"""

CREATE_AUTH_LOGS_TABLE: str = """
CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
"""

# ---------------------------------------------------------------------------
# Password Hasher & Rate Limiter Configuration
# ---------------------------------------------------------------------------
password_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)

RATE_LIMIT: int = 10
RATE_WINDOW_SECONDS: float = 1.0
_rate_lock: threading.Lock = threading.Lock()
_request_records: Dict[str, collections.deque] = {}

app = Flask(__name__)


def is_rate_limited(ip: str) -> bool:
    """Check if the given IP address exceeded 10 requests in the past second.

    Uses a sliding-window log. Evicts entries older than 1 second.

    Args:
        ip: Client IP address.

    Returns:
        True if the client exceeded the rate limit, False otherwise.
    """
    now = time.time()
    with _rate_lock:
        if ip not in _request_records:
            _request_records[ip] = collections.deque()
        queue = _request_records[ip]
        while queue and (now - queue[0]) >= RATE_WINDOW_SECONDS:
            queue.popleft()
        if len(queue) >= RATE_LIMIT:
            return True
        queue.append(now)
        return False


def reset_rate_limiter() -> None:
    """Clear all rate limiter records (useful for testing)."""
    with _rate_lock:
        _request_records.clear()


# ---------------------------------------------------------------------------
# AES Encryption / Decryption Helpers
# ---------------------------------------------------------------------------
def get_aes_key() -> bytes:
    """Retrieve and derive a 32-byte AES key from the NOT_MY_KEY env var.

    Returns:
        A 32-byte key suitable for AES-256.

    Raises:
        EnvironmentError: If NOT_MY_KEY is unset and no fallback is available.
    """
    raw_key = os.environ.get("NOT_MY_KEY")
    if not raw_key:
        raise EnvironmentError(
            "Environment variable NOT_MY_KEY is not set."
        )
    raw_bytes = raw_key.encode("utf-8")
    if len(raw_bytes) in (16, 24, 32):
        return raw_bytes
    return hashlib.sha256(raw_bytes).digest()


def encrypt_key(plaintext: bytes) -> bytes:
    """Encrypt plaintext bytes with AES-256-CBC using NOT_MY_KEY.

    Generates a fresh random 16-byte IV and prepends it to the ciphertext.

    Args:
        plaintext: The raw PEM private key bytes.

    Returns:
        iv (16 bytes) + ciphertext bytes.
    """
    key = get_aes_key()
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext


def decrypt_key(blob: bytes) -> bytes:
    """Decrypt a blob created by encrypt_key() back to plaintext bytes.

    Args:
        blob: iv (16 bytes) + ciphertext bytes.

    Returns:
        Original plaintext bytes.
    """
    if blob.startswith(b"-----BEGIN"):
        return blob
    if len(blob) < 16 or (len(blob) - 16) % 16 != 0:
        return blob
    try:
        key = get_aes_key()
        iv = blob[:16]
        ciphertext = blob[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()
    except Exception:
        return blob


# ---------------------------------------------------------------------------
# Database Management (All Parameterized)
# ---------------------------------------------------------------------------
def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Open and return a new SQLite database connection."""
    path = db_path if db_path is not None else DB_FILE
    return sqlite3.connect(path)


def init_db(db_path: Optional[str] = None) -> None:
    """Create keys, users, and auth_logs tables if they do not exist."""
    conn = get_db_connection(db_path)
    try:
        conn.execute(CREATE_KEYS_TABLE)
        conn.execute(CREATE_USERS_TABLE)
        conn.execute(CREATE_AUTH_LOGS_TABLE)
        conn.commit()
    except sqlite3.Error as err:
        conn.rollback()
        raise sqlite3.Error(f"Database init failed: {err}") from err
    finally:
        conn.close()


def save_key(
    pem_bytes: bytes, exp_timestamp: int, db_path: Optional[str] = None
) -> int:
    """Encrypt and insert a private key and its expiration into keys table.

    Args:
        pem_bytes: Plaintext PEM bytes of the private key.
        exp_timestamp: Expiration Unix epoch timestamp.
        db_path: Optional path to the database file.

    Returns:
        The auto-generated kid (integer primary key).
    """
    encrypted_blob = encrypt_key(pem_bytes)
    sql = "INSERT INTO keys (key, exp) VALUES (?, ?)"
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(sql, (encrypted_blob, exp_timestamp))
        conn.commit()
        return cursor.lastrowid
    except sqlite3.Error as err:
        conn.rollback()
        raise sqlite3.Error(f"Failed to save key: {err}") from err
    finally:
        conn.close()


def get_unexpired_key(
    db_path: Optional[str] = None,
) -> Optional[Tuple[int, bytes, int]]:
    """Retrieve and decrypt one non-expired private key from the database."""
    now_ts = int(datetime.now(timezone.utc).timestamp())
    sql = "SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1"
    conn = get_db_connection(db_path)
    try:
        row = conn.execute(sql, (now_ts,)).fetchone()
        if row is None:
            return None
        kid, blob, exp = row
        decrypted_pem = decrypt_key(blob)
        return kid, decrypted_pem, exp
    except sqlite3.Error as err:
        raise sqlite3.Error(f"Error querying unexpired key: {err}") from err
    finally:
        conn.close()


def get_expired_key(
    db_path: Optional[str] = None,
) -> Optional[Tuple[int, bytes, int]]:
    """Retrieve and decrypt one expired private key from the database."""
    now_ts = int(datetime.now(timezone.utc).timestamp())
    sql = "SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1"
    conn = get_db_connection(db_path)
    try:
        row = conn.execute(sql, (now_ts,)).fetchone()
        if row is None:
            return None
        kid, blob, exp = row
        decrypted_pem = decrypt_key(blob)
        return kid, decrypted_pem, exp
    except sqlite3.Error as err:
        raise sqlite3.Error(f"Error querying expired key: {err}") from err
    finally:
        conn.close()


def get_all_valid_keys(
    db_path: Optional[str] = None,
) -> List[Tuple[int, bytes, int]]:
    """Retrieve and decrypt all non-expired private keys from the database."""
    now_ts = int(datetime.now(timezone.utc).timestamp())
    sql = "SELECT kid, key, exp FROM keys WHERE exp > ?"
    conn = get_db_connection(db_path)
    try:
        rows = conn.execute(sql, (now_ts,)).fetchall()
        result = []
        for kid, blob, exp in rows:
            decrypted_pem = decrypt_key(blob)
            result.append((kid, decrypted_pem, exp))
        return result
    except sqlite3.Error as err:
        raise sqlite3.Error(f"Error querying valid keys: {err}") from err
    finally:
        conn.close()


def create_user(
    username: str,
    password_hash: str,
    email: Optional[str] = None,
    db_path: Optional[str] = None,
) -> int:
    """Insert a new user record into the users table.

    Args:
        username: Unique username.
        password_hash: Argon2-hashed password string.
        email: Optional unique email.
        db_path: Optional database file path.

    Returns:
        Auto-incremented user id.
    """
    sql = (
        "INSERT INTO users (username, password_hash, email) "
        "VALUES (?, ?, ?)"
    )
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(sql, (username, password_hash, email))
        conn.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError as err:
        conn.rollback()
        raise err
    except sqlite3.Error as err:
        conn.rollback()
        raise sqlite3.Error(f"Failed to create user: {err}") from err
    finally:
        conn.close()


def get_user_by_username(
    username: str, db_path: Optional[str] = None
) -> Optional[Tuple]:
    """Look up a user row by username."""
    sql = (
        "SELECT id, username, password_hash, email, date_registered, "
        "last_login FROM users WHERE username = ?"
    )
    conn = get_db_connection(db_path)
    try:
        return conn.execute(sql, (username,)).fetchone()
    except sqlite3.Error as err:
        raise sqlite3.Error(f"Error finding user: {err}") from err
    finally:
        conn.close()


def log_auth_request(
    request_ip: str,
    user_id: Optional[int],
    db_path: Optional[str] = None,
) -> int:
    """Record an authentication request in the auth_logs table.

    Args:
        request_ip: Client IP address.
        user_id: Optional foreign key to users.id.
        db_path: Optional database file path.

    Returns:
        The auto-generated log row id.
    """
    sql = "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)"
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(sql, (request_ip, user_id))
        conn.commit()
        return cursor.lastrowid
    except sqlite3.Error as err:
        conn.rollback()
        raise sqlite3.Error(f"Failed to log auth request: {err}") from err
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Cryptographic & JWK Helpers
# ---------------------------------------------------------------------------
def int_to_base64url(val: int) -> str:
    """Encode an integer into a base64url string without padding."""
    byte_length = max(1, (val.bit_length() + 7) // 8)
    val_bytes = val.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(val_bytes).rstrip(b"=").decode("utf-8")


def serialize_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialize an RSA private key to PKCS1 PEM bytes."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_private_key(pem_bytes: bytes) -> rsa.RSAPrivateKey:
    """Deserialize PEM bytes into an RSA private key instance."""
    return serialization.load_pem_private_key(pem_bytes, password=None)


def generate_and_store_key(
    expiry: datetime, key_size: int = 2048, db_path: Optional[str] = None
) -> int:
    """Generate a new RSA key pair and store the encrypted private key."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    pem_bytes = serialize_private_key(private_key)
    exp_ts = int(expiry.timestamp())
    return save_key(pem_bytes, exp_ts, db_path=db_path)


def key_row_to_jwk(row: Tuple[int, bytes, int]) -> Dict[str, Any]:
    """Convert a decrypted key row (kid, pem_bytes, exp) to a JWK dict."""
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
    """Retrieve all non-expired keys and build the JWKS dictionary."""
    rows = get_all_valid_keys(db_path=db_path)
    return {"keys": [key_row_to_jwk(row) for row in rows]}


def seed_initial_keys(db_path: Optional[str] = None) -> None:
    """Seed one valid key (+1 hr) and one expired key (-1 hr) if needed."""
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
    """Return all non-expired public keys in JWKS format per RFC 7517."""
    try:
        data = get_jwks()
        return jsonify(data), 200
    except sqlite3.Error as err:
        return jsonify(
            {"error": f"Database error retrieving JWKS: {str(err)}"}
        ), 500
    except Exception as err:
        return jsonify({"error": f"Failed to retrieve JWKS: {str(err)}"}), 500


@app.route("/register", methods=["POST"])
def register_endpoint() -> Any:
    """Register a new user, generating a secure UUIDv4 password.

    Expects JSON body: {"username": "...", "email": "..."}
    Returns JSON: {"password": "<generated_uuid>"} with HTTP 201 Created.
    """
    if not request.is_json:
        return jsonify({"error": "Request body must be JSON"}), 400

    body = request.get_json(silent=True) or {}
    username = body.get("username")
    email = body.get("email")

    if not username:
        return jsonify({"error": "username is required"}), 400

    generated_password = str(uuid.uuid4())
    password_hash = password_hasher.hash(generated_password)

    try:
        create_user(
            username=username, password_hash=password_hash, email=email
        )
    except sqlite3.IntegrityError:
        return jsonify(
            {"error": "User with this username or email already exists"}
        ), 409
    except sqlite3.Error as err:
        return jsonify({"error": f"Database registration error: {err}"}), 500

    return jsonify({"password": generated_password}), 201


@app.route("/auth", methods=["POST"])
def auth_endpoint() -> Any:
    """Issue a signed JWT using a decrypted private key from the database.

    Rate-limited to 10 requests per second per IP. Returns 429 when breached.
    Logs successful (rate-limit passing) requests to the auth_logs table.
    """
    client_ip = request.remote_addr or "127.0.0.1"

    # Enforce 10 req/s rate limit
    if is_rate_limited(client_ip):
        return jsonify({"error": "Too Many Requests"}), 429

    # Determine username (HTTP Basic Auth or JSON body or default mock)
    username = "userABC"
    if request.authorization and request.authorization.username:
        username = request.authorization.username
    elif request.is_json:
        body = request.get_json(silent=True) or {}
        username = body.get("username", username)

    # Resolve user_id and log the auth request (only succeeding requests)
    try:
        user_row = get_user_by_username(username)
        user_id = user_row[0] if user_row else None
        log_auth_request(request_ip=client_ip, user_id=user_id)
    except sqlite3.Error as err:
        return jsonify({"error": f"Failed to log auth request: {err}"}), 500

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


UNSUPPORTED_JWKS: List[str] = ["POST", "PUT", "DELETE", "PATCH"]
UNSUPPORTED_AUTH: List[str] = ["GET", "PUT", "DELETE", "PATCH"]
UNSUPPORTED_REGISTER: List[str] = ["GET", "PUT", "DELETE", "PATCH"]


@app.route("/.well-known/jwks.json", methods=UNSUPPORTED_JWKS)
@app.route("/jwks", methods=UNSUPPORTED_JWKS)
@app.route("/auth", methods=UNSUPPORTED_AUTH)
@app.route("/register", methods=UNSUPPORTED_REGISTER)
def method_not_allowed() -> Any:
    """Return HTTP 405 Method Not Allowed for unsupported HTTP verbs."""
    return jsonify({"error": "Method Not Allowed"}), 405


# ---------------------------------------------------------------------------
# Application Initialization
# ---------------------------------------------------------------------------
def setup_app(db_path: Optional[str] = None) -> None:
    """Initialize SQLite tables and seed keys on server startup."""
    init_db(db_path)
    # Ensure NOT_MY_KEY is set or set a default test key if missing
    if "NOT_MY_KEY" not in os.environ:
        os.environ["NOT_MY_KEY"] = "default_not_my_key_32_bytes_test"
    seed_initial_keys(db_path)


setup_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
