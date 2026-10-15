"""Unit and Integration Tests for JWKS Server — Project 2.

Tests cover db_manager, key_manager, and all Flask endpoints.
Run with:
    venv/bin/pytest test_app.py --cov=. --cov-report=term-missing -v
"""

import os
import sqlite3
import tempfile
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import pytest
import jwt

# ---------------------------------------------------------------------------
# Fixture: isolate each test with a fresh temporary database
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Redirect DB_FILE to a temp file and reinitialize for every test."""
    db_path = str(tmp_path / "test_keys.db")
    monkeypatch.setattr("db_manager.DB_FILE", db_path)
    monkeypatch.setattr("key_manager.db_manager.DB_FILE", db_path)

    import db_manager as dbm
    import key_manager as km

    dbm.initialize_db()
    km.initialize_keys()
    yield db_path


@pytest.fixture
def client(isolated_db):
    """Flask test client with testing mode enabled."""
    # Re-import app so setup_database() uses the patched DB path
    import main as m
    m.app.config["TESTING"] = True
    with m.app.test_client() as c:
        yield c


# ===========================================================================
# db_manager tests
# ===========================================================================

class TestDbManager:
    """Tests for the SQLite database manager module."""

    def test_initialize_db_creates_table(self, isolated_db):
        """initialize_db should create the keys table."""
        import db_manager as dbm
        conn = sqlite3.connect(isolated_db)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='keys'"
        )
        assert cursor.fetchone() is not None
        conn.close()

    def test_initialize_db_idempotent(self, isolated_db):
        """Calling initialize_db twice should not raise or duplicate tables."""
        import db_manager as dbm
        dbm.initialize_db()  # second call
        conn = sqlite3.connect(isolated_db)
        count = conn.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='keys'"
        ).fetchone()[0]
        assert count == 1
        conn.close()

    def test_save_key_returns_autoincrement_id(self, isolated_db):
        """save_key should return a positive integer kid."""
        import db_manager as dbm
        kid = dbm.save_key(b"fake-pem", int(datetime.now(timezone.utc).timestamp()) + 3600)
        assert isinstance(kid, int)
        assert kid >= 1

    def test_save_key_increments(self, isolated_db):
        """Each save_key call should return an incrementing kid."""
        import db_manager as dbm
        exp = int(datetime.now(timezone.utc).timestamp()) + 3600
        kid1 = dbm.save_key(b"key1", exp)
        kid2 = dbm.save_key(b"key2", exp)
        assert kid2 > kid1

    def test_get_unexpired_key_returns_valid_row(self, isolated_db):
        """get_unexpired_key should return a row whose exp is in the future."""
        import db_manager as dbm
        row = dbm.get_unexpired_key()
        assert row is not None
        kid, pem, exp = row
        assert exp > int(datetime.now(timezone.utc).timestamp())

    def test_get_unexpired_key_none_when_absent(self, isolated_db):
        """get_unexpired_key returns None if no valid key exists."""
        import db_manager as dbm
        # Remove all unexpired keys
        conn = sqlite3.connect(isolated_db)
        now_ts = int(datetime.now(timezone.utc).timestamp())
        conn.execute("DELETE FROM keys WHERE exp > ?", (now_ts,))
        conn.commit()
        conn.close()
        assert dbm.get_unexpired_key() is None

    def test_get_expired_key_returns_expired_row(self, isolated_db):
        """get_expired_key should return a row whose exp is in the past."""
        import db_manager as dbm
        row = dbm.get_expired_key()
        assert row is not None
        kid, pem, exp = row
        assert exp <= int(datetime.now(timezone.utc).timestamp())

    def test_get_expired_key_none_when_absent(self, isolated_db):
        """get_expired_key returns None if no expired key exists."""
        import db_manager as dbm
        conn = sqlite3.connect(isolated_db)
        now_ts = int(datetime.now(timezone.utc).timestamp())
        conn.execute("DELETE FROM keys WHERE exp <= ?", (now_ts,))
        conn.commit()
        conn.close()
        assert dbm.get_expired_key() is None

    def test_get_all_valid_keys_count(self, isolated_db):
        """get_all_valid_keys should return only unexpired rows."""
        import db_manager as dbm
        rows = dbm.get_all_valid_keys()
        # initialize_keys() added exactly one valid key
        assert len(rows) == 1

    def test_get_all_valid_keys_empty_when_none(self, isolated_db):
        """get_all_valid_keys returns empty list when no valid keys exist."""
        import db_manager as dbm
        conn = sqlite3.connect(isolated_db)
        now_ts = int(datetime.now(timezone.utc).timestamp())
        conn.execute("DELETE FROM keys WHERE exp > ?", (now_ts,))
        conn.commit()
        conn.close()
        assert dbm.get_all_valid_keys() == []


# ===========================================================================
# key_manager tests
# ===========================================================================

class TestKeyManager:
    """Tests for key generation, serialization, and JWKS formatting."""

    def test_bytes_to_base64url_no_padding(self):
        """Base64url encoding should strip '=' padding characters."""
        from key_manager import bytes_to_base64url
        result = bytes_to_base64url(b"hello world")
        assert "=" not in result
        assert "+" not in result
        assert "/" not in result

    def test_int_to_base64url_returns_string(self):
        """int_to_base64url should return a non-empty string."""
        from key_manager import int_to_base64url
        result = int_to_base64url(65537)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_serialize_deserialize_roundtrip(self):
        """Serializing and deserializing a key should yield equivalent keys."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from key_manager import serialize_private_key, deserialize_private_key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = serialize_private_key(private_key)
        recovered = deserialize_private_key(pem)
        # Compare public numbers to verify the round-trip preserved the key
        orig_nums = private_key.public_key().public_numbers()
        rec_nums = recovered.public_key().public_numbers()
        assert orig_nums.n == rec_nums.n
        assert orig_nums.e == rec_nums.e

    def test_generate_and_store_key_returns_kid(self, isolated_db):
        """generate_and_store_key should return a positive integer kid."""
        from key_manager import generate_and_store_key
        now = datetime.now(timezone.utc)
        kid = generate_and_store_key(now + timedelta(hours=2))
        assert isinstance(kid, int)
        assert kid >= 1

    def test_key_row_to_jwk_structure(self, isolated_db):
        """key_row_to_jwk should return a properly structured JWK dict."""
        import db_manager as dbm
        from key_manager import key_row_to_jwk
        row = dbm.get_unexpired_key()
        assert row is not None
        jwk = key_row_to_jwk(row)
        assert jwk["kty"] == "RSA"
        assert jwk["alg"] == "RS256"
        assert jwk["use"] == "sig"
        assert "kid" in jwk
        assert "n" in jwk
        assert "e" in jwk

    def test_get_jwks_contains_only_valid_keys(self, isolated_db):
        """get_jwks should return only unexpired keys."""
        from key_manager import get_jwks
        result = get_jwks()
        assert "keys" in result
        assert len(result["keys"]) == 1

    def test_get_key_for_auth_unexpired(self, isolated_db):
        """get_key_for_auth(expired=False) should return an unexpired row."""
        from key_manager import get_key_for_auth
        row = get_key_for_auth(expired=False)
        assert row is not None
        _, _, exp = row
        assert exp > int(datetime.now(timezone.utc).timestamp())

    def test_get_key_for_auth_expired(self, isolated_db):
        """get_key_for_auth(expired=True) should return an expired row."""
        from key_manager import get_key_for_auth
        row = get_key_for_auth(expired=True)
        assert row is not None
        _, _, exp = row
        assert exp <= int(datetime.now(timezone.utc).timestamp())

    def test_get_key_for_auth_raises_when_no_unexpired(self, isolated_db):
        """get_key_for_auth raises ValueError when no unexpired key exists."""
        import db_manager as dbm
        from key_manager import get_key_for_auth
        conn = sqlite3.connect(isolated_db)
        now_ts = int(datetime.now(timezone.utc).timestamp())
        conn.execute("DELETE FROM keys WHERE exp > ?", (now_ts,))
        conn.commit()
        conn.close()
        with pytest.raises(ValueError, match="unexpired"):
            get_key_for_auth(expired=False)

    def test_get_key_for_auth_raises_when_no_expired(self, isolated_db):
        """get_key_for_auth raises ValueError when no expired key exists."""
        import db_manager as dbm
        from key_manager import get_key_for_auth
        conn = sqlite3.connect(isolated_db)
        now_ts = int(datetime.now(timezone.utc).timestamp())
        conn.execute("DELETE FROM keys WHERE exp <= ?", (now_ts,))
        conn.commit()
        conn.close()
        with pytest.raises(ValueError, match="expired"):
            get_key_for_auth(expired=True)

    def test_initialize_keys_adds_two_rows(self, isolated_db):
        """initialize_keys should have added exactly 2 rows (one valid, one expired)."""
        import db_manager as dbm
        conn = sqlite3.connect(isolated_db)
        count = conn.execute("SELECT count(*) FROM keys").fetchone()[0]
        conn.close()
        # isolated_db fixture calls initialize_keys() once
        assert count == 2


# ===========================================================================
# Flask endpoint integration tests
# ===========================================================================

class TestJWKSEndpoint:
    """Integration tests for GET /.well-known/jwks.json and aliases."""

    def test_root_endpoint(self, client):
        res = client.get("/")
        assert res.status_code == 200
        assert "keys" in res.get_json()

    def test_jwks_well_known(self, client):
        res = client.get("/.well-known/jwks.json")
        assert res.status_code == 200
        data = res.get_json()
        assert "keys" in data
        assert len(data["keys"]) == 1

    def test_jwks_alias(self, client):
        res = client.get("/jwks")
        assert res.status_code == 200
        assert "keys" in res.get_json()

    def test_jwks_key_structure(self, client):
        """Each key in JWKS should have required JWK fields."""
        res = client.get("/.well-known/jwks.json")
        key = res.get_json()["keys"][0]
        for field in ("kty", "alg", "use", "kid", "n", "e"):
            assert field in key

    def test_jwks_post_not_allowed(self, client):
        assert client.post("/jwks").status_code == 405

    def test_jwks_put_not_allowed(self, client):
        assert client.put("/jwks").status_code == 405

    def test_jwks_delete_not_allowed(self, client):
        assert client.delete("/jwks").status_code == 405

    def test_jwks_error_handling(self, client):
        with patch("key_manager.get_jwks", side_effect=RuntimeError("boom")):
            res = client.get("/jwks")
            assert res.status_code == 500
            assert "Failed to retrieve JWKS" in res.get_json()["error"]


class TestAuthEndpoint:
    """Integration tests for POST /auth."""

    def test_auth_unexpired_status(self, client):
        res = client.post("/auth")
        assert res.status_code == 200

    def test_auth_unexpired_content_type(self, client):
        res = client.post("/auth")
        assert "application/jwt" in res.content_type

    def test_auth_unexpired_jwt_header(self, client):
        """Returned JWT should have RS256 algorithm and a kid."""
        res = client.post("/auth")
        token = res.get_data(as_text=True)
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "RS256"
        assert "kid" in header

    def test_auth_unexpired_jwt_payload(self, client):
        """Returned JWT payload exp should be in the future."""
        res = client.post("/auth")
        token = res.get_data(as_text=True)
        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload["exp"] > datetime.now(timezone.utc).timestamp()

    def test_auth_expired_jwt_payload(self, client):
        """JWT signed with expired key should have a past exp."""
        res = client.post("/auth?expired=true")
        assert res.status_code == 200
        token = res.get_data(as_text=True)
        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload["exp"] <= datetime.now(timezone.utc).timestamp()

    def test_auth_expired_param_numeric(self, client):
        """?expired=1 should also trigger expired signing."""
        res = client.post("/auth?expired=1")
        assert res.status_code == 200
        token = res.get_data(as_text=True)
        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload["exp"] <= datetime.now(timezone.utc).timestamp()

    def test_auth_with_json_body(self, client):
        """JSON body with username/password should be accepted."""
        res = client.post(
            "/auth",
            json={"username": "userABC", "password": "password123"},
        )
        assert res.status_code == 200
        token = res.get_data(as_text=True)
        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload["sub"] == "userABC"

    def test_auth_with_basic_auth(self, client):
        """HTTP Basic Auth credentials should be accepted."""
        import base64
        creds = base64.b64encode(b"userABC:password123").decode()
        res = client.post(
            "/auth",
            headers={"Authorization": f"Basic {creds}"},
        )
        assert res.status_code == 200
        token = res.get_data(as_text=True)
        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload["sub"] == "userABC"

    def test_auth_get_not_allowed(self, client):
        assert client.get("/auth").status_code == 405

    def test_auth_put_not_allowed(self, client):
        assert client.put("/auth").status_code == 405

    def test_auth_jwt_encode_error(self, client):
        with patch("jwt.encode", side_effect=jwt.PyJWTError("fail")):
            res = client.post("/auth")
            assert res.status_code == 500
            assert "JWT encoding failed" in res.get_json()["error"]

    def test_auth_generic_error(self, client):
        with patch("jwt.encode", side_effect=RuntimeError("unexpected")):
            res = client.post("/auth")
            assert res.status_code == 500
            assert "Internal server error" in res.get_json()["error"]

    def test_auth_no_key_error(self, client):
        """If no valid key exists in DB, /auth should return 500."""
        with patch("key_manager.get_key_for_auth", side_effect=ValueError("no key")):
            res = client.post("/auth")
            assert res.status_code == 500
