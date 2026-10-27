"""Database management module for JWKS Server (Project 3).

Handles creation, reading, and writing of:
  - AES-encrypted RSA private keys  (keys table)
  - User accounts with Argon2-hashed passwords  (users table)
  - Authentication request logs  (auth_logs table)

All SQL queries use parameterized placeholders (?) to prevent injection.
The AES encryption key is read from the environment variable NOT_MY_KEY.
"""

import os
import sqlite3
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Database file
# ---------------------------------------------------------------------------
DB_FILE = "totally_not_my_privateKeys.db"

# ---------------------------------------------------------------------------
# Table DDL statements (per project spec)
# ---------------------------------------------------------------------------
CREATE_KEYS_TABLE = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
"""

CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
)
"""

CREATE_AUTH_LOGS_TABLE = """
CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
"""


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

def get_connection() -> sqlite3.Connection:
    """Open and return a connection to the SQLite database file."""
    conn = sqlite3.connect(DB_FILE)
    conn.isolation_level = None  # autocommit mode
    return conn


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------

def initialize_db() -> None:
    """Create all required tables if they do not already exist."""
    conn = get_connection()
    try:
        conn.execute(CREATE_KEYS_TABLE)
        conn.execute(CREATE_USERS_TABLE)
        conn.execute(CREATE_AUTH_LOGS_TABLE)
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# AES encryption helpers
# ---------------------------------------------------------------------------

def _get_aes_key() -> bytes:
    """Read and validate the AES key from the NOT_MY_KEY environment variable.

    The env-var value is UTF-8 encoded and then hashed/padded to exactly
    32 bytes (AES-256) so that any string value works safely.

    Returns:
        A 32-byte key suitable for AES-256 encryption.

    Raises:
        EnvironmentError: If NOT_MY_KEY is not set.
    """
    raw = os.environ.get("NOT_MY_KEY")
    if not raw:
        raise EnvironmentError(
            "NOT_MY_KEY environment variable is not set. "
            "Export it before starting the server."
        )
    import hashlib
    # SHA-256 of the raw string gives a stable, safe 32-byte key
    return hashlib.sha256(raw.encode()).digest()


def encrypt_key(plaintext: bytes) -> bytes:
    """Encrypt plaintext bytes with AES-256-CBC using NOT_MY_KEY.

    Prepends the random 16-byte IV to the ciphertext so that it can be
    recovered at decryption time (the IV is not a secret).

    Args:
        plaintext: Raw bytes to encrypt (e.g. PEM-encoded private key).

    Returns:
        iv (16 bytes) + ciphertext bytes.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding

    aes_key = _get_aes_key()
    iv = os.urandom(16)  # fresh random IV for every encryption

    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return iv + ciphertext  # IV is prepended, not secret


def decrypt_key(blob: bytes) -> bytes:
    """Decrypt a blob produced by encrypt_key() back to plaintext bytes.

    Args:
        blob: iv (16 bytes) + ciphertext bytes as stored in the DB.

    Returns:
        Original plaintext bytes.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding

    aes_key = _get_aes_key()
    iv, ciphertext = blob[:16], blob[16:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ---------------------------------------------------------------------------
# keys table operations
# ---------------------------------------------------------------------------

def save_key(pem_bytes: bytes, exp_timestamp: int) -> int:
    """Encrypt and insert a PEM-encoded private key into the keys table.

    Args:
        pem_bytes: PKCS8 PEM bytes of the RSA private key.
        exp_timestamp: Unix timestamp for key expiration.

    Returns:
        The auto-assigned kid (integer primary key).
    """
    encrypted = encrypt_key(pem_bytes)
    sql = "INSERT INTO keys (key, exp) VALUES (?, ?)"
    conn = get_connection()
    try:
        cursor = conn.execute(sql, (encrypted, exp_timestamp))
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def _decrypt_row(row: tuple) -> tuple:
    """Return a key row with its encrypted blob decrypted to PEM bytes."""
    kid, blob, exp = row
    return (kid, decrypt_key(bytes(blob)), exp)


def get_unexpired_key() -> tuple | None:
    """Retrieve and decrypt one valid (unexpired) key row.

    Returns:
        A (kid, pem_bytes, exp) tuple, or None if none found.
    """
    now_ts = int(datetime.now(timezone.utc).timestamp())
    sql = "SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1"
    conn = get_connection()
    try:
        row = conn.execute(sql, (now_ts,)).fetchone()
    finally:
        conn.close()
    return _decrypt_row(row) if row else None


def get_expired_key() -> tuple | None:
    """Retrieve and decrypt one expired key row.

    Returns:
        A (kid, pem_bytes, exp) tuple, or None if none found.
    """
    now_ts = int(datetime.now(timezone.utc).timestamp())
    sql = "SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1"
    conn = get_connection()
    try:
        row = conn.execute(sql, (now_ts,)).fetchone()
    finally:
        conn.close()
    return _decrypt_row(row) if row else None


def get_all_valid_keys() -> list[tuple]:
    """Retrieve and decrypt all non-expired key rows.

    Returns:
        A list of (kid, pem_bytes, exp) tuples.
    """
    now_ts = int(datetime.now(timezone.utc).timestamp())
    sql = "SELECT kid, key, exp FROM keys WHERE exp > ?"
    conn = get_connection()
    try:
        rows = conn.execute(sql, (now_ts,)).fetchall()
    finally:
        conn.close()
    return [_decrypt_row(r) for r in rows]


# ---------------------------------------------------------------------------
# users table operations
# ---------------------------------------------------------------------------

def create_user(username: str, password_hash: str, email: str) -> int:
    """Insert a new user record into the users table.

    Args:
        username: Unique username string.
        password_hash: Argon2-hashed password string.
        email: User email address (may be None).

    Returns:
        The auto-assigned user id.

    Raises:
        sqlite3.IntegrityError: If username or email already exists.
    """
    sql = "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)"
    conn = get_connection()
    try:
        cursor = conn.execute(sql, (username, password_hash, email))
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def get_user_by_username(username: str) -> tuple | None:
    """Look up a user row by username.

    Returns:
        A (id, username, password_hash, email, date_registered, last_login)
        tuple, or None if not found.
    """
    sql = (
        "SELECT id, username, password_hash, email, date_registered, last_login "
        "FROM users WHERE username = ?"
    )
    conn = get_connection()
    try:
        row = conn.execute(sql, (username,)).fetchone()
    finally:
        conn.close()
    return row


# ---------------------------------------------------------------------------
# auth_logs table operations
# ---------------------------------------------------------------------------

def log_auth_request(request_ip: str, user_id: int | None) -> None:
    """Insert an authentication log entry.

    Args:
        request_ip: IP address of the requester.
        user_id: DB id of the authenticating user (or None).
    """
    sql = "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)"
    conn = get_connection()
    try:
        conn.execute(sql, (request_ip, user_id))
        conn.commit()
    finally:
        conn.close()
