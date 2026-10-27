"""Key management module for JWKS Server (Project 3).

Generates RSA key pairs, serializes/deserializes them to/from the SQLite
database (via db_manager which handles AES encryption), and formats public
keys into JWKS format per RFC 7517.
"""

import base64
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import db_manager


def bytes_to_base64url(b: bytes) -> str:
    """Encode bytes into a base64url string without padding characters."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("utf-8")


def int_to_base64url(val: int) -> str:
    """Convert an integer to its big-endian bytes, then base64url encode."""
    byte_length = max(1, (val.bit_length() + 7) // 8)
    val_bytes = val.to_bytes(byte_length, byteorder="big")
    return bytes_to_base64url(val_bytes)


def serialize_private_key(private_key) -> bytes:
    """Serialize an RSA private key to unencrypted PKCS8 PEM bytes."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_private_key(pem_bytes: bytes):
    """Load an RSA private key object from PEM bytes."""
    return serialization.load_pem_private_key(pem_bytes, password=None)


def generate_and_store_key(expiry: datetime, key_size: int = 2048) -> int:
    """Generate an RSA key pair, AES-encrypt it, and persist it to the DB.

    Args:
        expiry: UTC datetime when the key expires.
        key_size: RSA key size in bits (default 2048).

    Returns:
        The DB-assigned kid (integer primary key).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    pem_bytes = serialize_private_key(private_key)
    exp_ts = int(expiry.timestamp())
    # db_manager.save_key handles AES encryption before writing to DB
    return db_manager.save_key(pem_bytes, exp_ts)


def key_row_to_jwk(row: tuple) -> Dict[str, Any]:
    """Convert a decrypted DB row (kid, pem_bytes, exp) to a JWK dict.

    Args:
        row: Tuple of (kid, pem_bytes, exp) — pem_bytes already decrypted.

    Returns:
        A JWK dict with kty, alg, use, kid, n, and e fields.
    """
    kid, pem_bytes, _ = row
    private_key = deserialize_private_key(pem_bytes)
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": str(kid),
        "n": int_to_base64url(numbers.n),
        "e": int_to_base64url(numbers.e),
    }


def get_jwks() -> Dict[str, List[Dict[str, Any]]]:
    """Read all valid (unexpired) keys from DB and return a JWKS payload."""
    rows = db_manager.get_all_valid_keys()
    return {"keys": [key_row_to_jwk(row) for row in rows]}


def get_key_for_auth(expired: bool = False) -> tuple:
    """Retrieve a decrypted key row from the DB for JWT signing.

    Args:
        expired: If True, fetch an expired key; otherwise an unexpired one.

    Returns:
        A (kid, pem_bytes, exp) tuple — pem_bytes already decrypted.

    Raises:
        ValueError: If no matching key is found in the database.
    """
    row = db_manager.get_expired_key() if expired else db_manager.get_unexpired_key()
    if row is None:
        label = "expired" if expired else "unexpired"
        raise ValueError(f"No {label} key found in database")
    return row


def initialize_keys() -> None:
    """Generate and store the initial RSA key pairs on server startup.

    Creates one key expiring in 1 hour (valid) and one that expired
    1 hour ago (supports the ?expired query parameter in tests).
    """
    now = datetime.now(timezone.utc)
    generate_and_store_key(expiry=now + timedelta(hours=1))   # valid key
    generate_and_store_key(expiry=now - timedelta(hours=1))   # expired key
