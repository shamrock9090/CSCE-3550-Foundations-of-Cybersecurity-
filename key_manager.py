"""Key management module for JWKS Server.

Generates RSA key pairs, associates dynamic Key IDs (kid) and expiration times,
and formats public keys into JWKS format per RFC 7517.
"""

import base64
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any
from cryptography.hazmat.primitives.asymmetric import rsa


def bytes_to_base64url(b: bytes) -> str:
    """Encode bytes into base64url string without padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("utf-8")


def int_to_base64url(val: int) -> str:
    """Convert integer to big-endian byte array & base64url encode."""
    byte_length = max(1, (val.bit_length() + 7) // 8)
    val_bytes = val.to_bytes(byte_length, byteorder="big")
    return bytes_to_base64url(val_bytes)


class KeyEntry:
    """Represents an RSA key pair with kid and expiration timestamp."""

    def __init__(
        self, expiry: datetime, kid: str = None, key_size: int = 2048
    ):
        self.kid = kid or str(uuid.uuid4())
        self.expiry = expiry
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        self.public_key = self.private_key.public_key()

    def is_expired(self, current_time: datetime = None) -> bool:
        """Check if key expired compared to current or given time."""
        if current_time is None:
            current_time = datetime.now(timezone.utc)
        return self.expiry <= current_time

    def to_jwk(self) -> Dict[str, Any]:
        """Convert public key to a JWK dictionary per RFC 7517."""
        numbers = self.public_key.public_numbers()
        return {
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": self.kid,
            "n": int_to_base64url(numbers.n),
            "e": int_to_base64url(numbers.e),
        }


class KeyManager:
    """Manages collection of RSA keys and JWKS output."""

    def __init__(self):
        self.keys: List[KeyEntry] = []
        self.generate_initial_keys()

    def generate_initial_keys(self):
        """Generate one unexpired and one expired key pair."""
        now = datetime.now(timezone.utc)

        # Unexpired key pair (valid for 1 hour into future)
        unexpired_key = KeyEntry(
            expiry=now + timedelta(hours=1),
        )
        self.keys.append(unexpired_key)

        # Expired key pair (expired 1 hour in the past)
        expired_key = KeyEntry(
            expiry=now - timedelta(hours=1),
        )
        self.keys.append(expired_key)

    def add_key(self, expiry: datetime, kid: str = None) -> KeyEntry:
        """Dynamically create and add a new RSA key entry."""
        key_entry = KeyEntry(expiry=expiry, kid=kid)
        self.keys.append(key_entry)
        return key_entry

    def get_jwks(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get JWKS containing only valid (unexpired) public keys."""
        now = datetime.now(timezone.utc)
        valid_keys = [
            key.to_jwk() for key in self.keys if not key.is_expired(now)
        ]
        return {"keys": valid_keys}

    def get_key(self, expired: bool = False) -> KeyEntry:
        """Retrieve an expired or unexpired key entry."""
        now = datetime.now(timezone.utc)
        for key in self.keys:
            if expired and key.is_expired(now):
                return key
            if not expired and not key.is_expired(now):
                return key

        raise ValueError(
            f"No {'expired' if expired else 'unexpired'} key available"
        )
