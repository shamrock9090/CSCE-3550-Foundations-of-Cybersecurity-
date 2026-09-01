"""Unit and Integration Tests for JWKS Server."""

from datetime import datetime, timezone, timedelta
from unittest.mock import patch
import pytest
import jwt
from key_manager import (
    bytes_to_base64url,
    int_to_base64url,
    KeyEntry,
    KeyManager,
)
from main import app


@pytest.fixture
def client():
    """Flask test client fixture."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# --- KeyManager Unit Tests ---

def test_bytes_to_base64url():
    data = b"hello world"
    encoded = bytes_to_base64url(data)
    assert "=" not in encoded
    assert "+" not in encoded
    assert "/" not in encoded


def test_int_to_base64url():
    val = 65537
    encoded = int_to_base64url(val)
    assert isinstance(encoded, str)
    assert len(encoded) > 0


def test_key_entry_expiration():
    now = datetime.now(timezone.utc)
    future_key = KeyEntry(now + timedelta(hours=1), kid="k1")
    past_key = KeyEntry(now - timedelta(hours=1), kid="k2")

    assert not future_key.is_expired(now)
    assert past_key.is_expired(now)


def test_key_entry_to_jwk():
    now = datetime.now(timezone.utc)
    key = KeyEntry(now + timedelta(hours=1), kid="k1")
    jwk = key.to_jwk()

    assert jwk["kty"] == "RSA"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert jwk["kid"] == "k1"
    assert "n" in jwk
    assert "e" in jwk


def test_key_manager_get_jwks():
    km = KeyManager()
    jwks = km.get_jwks()

    assert "keys" in jwks
    assert len(jwks["keys"]) == 1
    unexpired_kid = km.get_key(expired=False).kid
    assert jwks["keys"][0]["kid"] == unexpired_kid


def test_key_manager_add_key():
    km = KeyManager()
    now = datetime.now(timezone.utc)
    new_key = km.add_key(now + timedelta(hours=2), kid="custom-id")
    assert new_key.kid == "custom-id"
    assert len(km.get_jwks()["keys"]) == 2


def test_key_manager_get_key():
    km = KeyManager()
    unexpired = km.get_key(expired=False)
    assert not unexpired.is_expired()

    expired = km.get_key(expired=True)
    assert expired.is_expired()


def test_key_manager_no_key_error():
    km = KeyManager()
    km.keys = []  # Clear all keys
    with pytest.raises(ValueError):
        km.get_key(expired=False)


# --- Endpoint Integration Tests ---

def test_jwks_endpoint(client):
    res = client.get("/.well-known/jwks.json")
    assert res.status_code == 200
    data = res.get_json()
    assert "keys" in data
    assert len(data["keys"]) == 1


def test_jwks_alias_endpoint(client):
    res = client.get("/jwks")
    assert res.status_code == 200
    data = res.get_json()
    assert "keys" in data


def test_jwks_method_not_allowed(client):
    res = client.post("/jwks")
    assert res.status_code == 405


def test_auth_unexpired(client):
    res = client.post("/auth")
    assert res.status_code == 200
    token_str = res.get_data(as_text=True)

    header = jwt.get_unverified_header(token_str)
    assert "kid" in header
    assert header["alg"] == "RS256"

    payload = jwt.decode(token_str, options={"verify_signature": False})
    assert payload["sub"] == "mock-user-123"
    assert payload["exp"] > datetime.now(timezone.utc).timestamp()


def test_auth_expired(client):
    res = client.post("/auth?expired=true")
    assert res.status_code == 200
    token_str = res.get_data(as_text=True)

    header = jwt.get_unverified_header(token_str)
    assert "kid" in header
    assert header["alg"] == "RS256"

    payload = jwt.decode(token_str, options={"verify_signature": False})
    assert payload["exp"] < datetime.now(timezone.utc).timestamp()


def test_auth_expired_numeric_param(client):
    res = client.post("/auth?expired=1")
    assert res.status_code == 200
    token_str = res.get_data(as_text=True)

    payload = jwt.decode(token_str, options={"verify_signature": False})
    assert payload["exp"] < datetime.now(timezone.utc).timestamp()


def test_auth_method_not_allowed(client):
    res = client.get("/auth")
    assert res.status_code == 405


def test_auth_jwt_encoding_error(client):
    with patch("jwt.encode", side_effect=jwt.PyJWTError("Encoding error")):
        res = client.post("/auth")
        assert res.status_code == 500
        assert "JWT encoding failed" in res.get_json()["error"]


def test_auth_generic_error(client):
    with patch("jwt.encode", side_effect=RuntimeError("Unexpected")):
        res = client.post("/auth")
        assert res.status_code == 500
        assert "Internal server error" in res.get_json()["error"]


def test_jwks_generic_error(client):
    with patch(
        "key_manager.KeyManager.get_jwks",
        side_effect=RuntimeError("JWKS Err"),
    ):
        res = client.get("/jwks")
        assert res.status_code == 500
        assert "Failed to retrieve JWKS" in res.get_json()["error"]
