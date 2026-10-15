"""Database management module for JWKS Server (Project 2).

Handles creation, reading, and writing of RSA private keys
to a SQLite database using parameterized queries to prevent
SQL injection attacks.
"""

import sqlite3
from datetime import datetime, timezone

# Required DB filename per project spec
DB_FILE = "totally_not_my_privateKeys.db"

# SQL to create the keys table if it doesn't already exist
CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
"""


def get_connection() -> sqlite3.Connection:
    """Open and return a connection to the SQLite database file."""
    conn = sqlite3.connect(DB_FILE)
    return conn


def initialize_db() -> None:
    """Create the SQLite DB file and keys table if they don't exist."""
    with get_connection() as conn:
        conn.execute(CREATE_TABLE_SQL)
        conn.commit()


def save_key(pem_bytes: bytes, exp_timestamp: int) -> int:
    """Insert a serialized private key and its expiry into the DB.

    Args:
        pem_bytes: PEM-encoded private key bytes (PKCS8 format).
        exp_timestamp: Unix timestamp (integer) for key expiration.

    Returns:
        The auto-assigned kid (integer primary key) of the new row.
    """
    # Use parameterized query to prevent SQL injection
    sql = "INSERT INTO keys (key, exp) VALUES (?, ?)"
    with get_connection() as conn:
        cursor = conn.execute(sql, (pem_bytes, exp_timestamp))
        conn.commit()
        return cursor.lastrowid


def get_unexpired_key() -> tuple | None:
    """Retrieve one valid (unexpired) key row from the DB.

    Returns:
        A (kid, pem_bytes, exp) tuple, or None if none found.
    """
    now_ts = int(datetime.now(timezone.utc).timestamp())
    # Parameterized query: only select keys with exp > current time
    sql = "SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1"
    with get_connection() as conn:
        row = conn.execute(sql, (now_ts,)).fetchone()
    return row


def get_expired_key() -> tuple | None:
    """Retrieve one expired key row from the DB.

    Returns:
        A (kid, pem_bytes, exp) tuple, or None if none found.
    """
    now_ts = int(datetime.now(timezone.utc).timestamp())
    # Parameterized query: only select keys with exp <= current time
    sql = "SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1"
    with get_connection() as conn:
        row = conn.execute(sql, (now_ts,)).fetchone()
    return row


def get_all_valid_keys() -> list[tuple]:
    """Retrieve all non-expired key rows from the DB.

    Returns:
        A list of (kid, pem_bytes, exp) tuples.
    """
    now_ts = int(datetime.now(timezone.utc).timestamp())
    # Parameterized query: fetch all rows with exp > current time
    sql = "SELECT kid, key, exp FROM keys WHERE exp > ?"
    with get_connection() as conn:
        rows = conn.execute(sql, (now_ts,)).fetchall()
    return rows
