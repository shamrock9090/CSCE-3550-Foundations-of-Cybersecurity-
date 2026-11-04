"""Unit and Integration Tests for JWKS Server (Project 2).

Tests cover SQLite database operations, RSA key generation & serialization,
JWKS formatting per RFC 7517, and Flask REST endpoints.
"""

import base64
import os
import sqlite3
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import jwt
import pytest

import project2


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """Provide an isolated temporary SQLite database for each test."""
    db_path = str(tmp_path / "test_project2.db")
    monkeypatch.setattr(project2, "DB_FILE", db_path)
    project2.init_db(db_path)
    project2.seed_initial_keys(db_path)
    yield db_path


@pytest.fixture
def client(temp_db):
    """Provide a Flask test client configured for the isolated database."""
    project2.app.config["TESTING"] = True
    with project2.app.test_client() as test_client:
        yield test_client


class TestDatabaseOperations:
    """Tests for SQLite database functions in project2.py."""

    def test_init_db_creates_keys_table(self, temp_db):
        """init_db should create the keys table with expected columns."""
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='keys'"
        )
        assert cursor.fetchone() is not None

        cursor.execute("PRAGMA table_info(keys)")
        columns = {col[1]: col[2] for col in cursor.fetchall()}
        assert "kid" in columns
        assert "key" in columns
        assert "exp" in columns
        conn.close()

    def test_init_db_idempotent(self, temp_db):
        """Calling init_db multiple times should not raise errors."""
        project2.init_db(temp_db)
        project2.init_db(temp_db)
        conn = sqlite3.connect(temp_db)
        count = conn.execute(
            "SELECT count(*) FROM sqlite_master "
            "WHERE type='table' AND name='keys'"
        ).fetchone()[0]
        conn.close()
        assert count == 1

    def test_save_key_and_autoincrement(self, temp_db):
        """save_key should insert a row and return an incrementing kid."""
        exp = int(datetime.now(timezone.utc).timestamp()) + 3600
        kid1 = project2.save_key(b"test_key_1", exp, db_path=temp_db)
        kid2 = project2.save_key(b"test_key_2", exp, db_path=temp_db)
        assert isinstance(kid1, int)
        assert isinstance(kid2, int)
        assert kid2 > kid1

    def test_get_unexpired_key_returns_valid_row(self, temp_db):
        """get_unexpired_key should return a key with exp > current time."""
        row = project2.get_unexpired_key(db_path=temp_db)
        assert row is not None
        kid, key_bytes, exp = row
        assert exp > int(datetime.now(timezone.utc).timestamp())

    def test_get_unexpired_key_none_when_empty(self, temp_db):
        """get_unexpired_key returns None when no unexpired keys exist."""
        conn = sqlite3.connect(temp_db)
        now_ts = int(datetime.now(timezone.utc).timestamp())
        conn.execute("DELETE FROM keys WHERE exp > ?", (now_ts,))
        conn.commit()
        conn.close()

        assert project2.get_unexpired_key(db_path=temp_db) is None

    def test_get_expired_key_returns_expired_row(self, temp_db):
        """get_expired_key should return a key with exp <= current time."""
        row = project2.get_expired_key(db_path=temp_db)
        assert row is not None
        kid, key_bytes, exp = row
        assert exp <= int(datetime.now(timezone.utc).timestamp())

    def test_get_expired_key_none_when_empty(self, temp_db):
        """get_expired_key returns None when no expired keys exist."""
        conn = sqlite3.connect(temp_db)
        now_ts = int(datetime.now(timezone.utc).timestamp())
        conn.execute("DELETE FROM keys WHERE exp <= ?", (now_ts,))
        conn.commit()
        conn.close()

        assert project2.get_expired_key(db_path=temp_db) is None

    def test_get_all_valid_keys(self, temp_db):
        """get_all_valid_keys returns only non-expired rows."""
        now = datetime.now(timezone.utc)
        project2.generate_and_store_key(
            now + timedelta(hours=2), db_path=temp_db
        )
        project2.generate_and_store_key(
            now - timedelta(hours=2), db_path=temp_db
        )

        rows = project2.get_all_valid_keys(db_path=temp_db)
        now_ts = int(now.timestamp())
        for row in rows:
            assert row[2] > now_ts

    def test_db_error_handling(self, temp_db):
        """Database helpers raise sqlite3.Error on internal failure."""
        with patch("sqlite3.connect") as mock_connect:
            mock_conn = MagicMock()
            mock_conn.execute.side_effect = sqlite3.OperationalError(
                "disk I/O"
            )
            mock_connect.return_value = mock_conn

            with pytest.raises(sqlite3.Error):
                project2.init_db(temp_db)

            with pytest.raises(sqlite3.Error):
                project2.save_key(b"key", 12345, db_path=temp_db)

            with pytest.raises(sqlite3.Error):
                project2.get_unexpired_key(db_path=temp_db)

            with pytest.raises(sqlite3.Error):
                project2.get_expired_key(db_path=temp_db)

            with pytest.raises(sqlite3.Error):
                project2.get_all_valid_keys(db_path=temp_db)


class TestKeyManagement:
    """Tests for cryptographic key generation and conversion."""

    def test_int_to_base64url(self):
        """int_to_base64url should convert numbers per RFC 7515."""
        assert project2.int_to_base64url(65537) == "AQAB"
        assert "=" not in project2.int_to_base64url(123456789)

    def test_key_serialization_roundtrip(self):
        """Serializing and deserializing a private key should preserve it."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        original = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        pem = project2.serialize_private_key(original)
        assert b"BEGIN RSA PRIVATE KEY" in pem

        restored = project2.deserialize_private_key(pem)
        assert (
            original.public_key().public_numbers().n
            == restored.public_key().public_numbers().n
        )

    def test_seed_initial_keys_avoids_duplicate_creation(self, temp_db):
        """seed_initial_keys should not create keys if they already exist."""
        conn = sqlite3.connect(temp_db)
        count_before = conn.execute("SELECT count(*) FROM keys").fetchone()[0]
        conn.close()

        project2.seed_initial_keys(temp_db)

        conn = sqlite3.connect(temp_db)
        count_after = conn.execute("SELECT count(*) FROM keys").fetchone()[0]
        conn.close()

        assert count_before == count_after

    def test_key_row_to_jwk_format(self, temp_db):
        """key_row_to_jwk produces correct JWK dictionary structure."""
        row = project2.get_unexpired_key(db_path=temp_db)
        jwk = project2.key_row_to_jwk(row)
        assert jwk["kty"] == "RSA"
        assert jwk["alg"] == "RS256"
        assert jwk["use"] == "sig"
        assert jwk["kid"] == str(row[0])
        assert isinstance(jwk["n"], str)
        assert isinstance(jwk["e"], str)


class TestJWKSEndpoint:
    """Tests for the JWKS endpoint."""

    def test_jwks_standard_route(self, client):
        """GET /.well-known/jwks.json returns 200 and keys list."""
        res = client.get("/.well-known/jwks.json")
        assert res.status_code == 200
        data = res.get_json()
        assert "keys" in data
        assert len(data["keys"]) >= 1

    def test_jwks_route_aliases(self, client):
        """GET / and GET /jwks should also return the JWKS."""
        res1 = client.get("/jwks")
        assert res1.status_code == 200
        assert "keys" in res1.get_json()

        res2 = client.get("/")
        assert res2.status_code == 200
        assert "keys" in res2.get_json()

    def test_jwks_empty_when_no_valid_keys(self, client, temp_db):
        """JWKS returns empty keys array when no valid keys are in DB."""
        conn = sqlite3.connect(temp_db)
        now_ts = int(datetime.now(timezone.utc).timestamp())
        conn.execute("DELETE FROM keys WHERE exp > ?", (now_ts,))
        conn.commit()
        conn.close()

        res = client.get("/.well-known/jwks.json")
        assert res.status_code == 200
        assert res.get_json() == {"keys": []}

    def test_jwks_error_handling(self, client):
        """JWKS returns 500 when an unexpected exception occurs."""
        with patch("project2.get_jwks", side_effect=RuntimeError("db error")):
            res = client.get("/.well-known/jwks.json")
            assert res.status_code == 500
            assert "Failed to retrieve JWKS" in res.get_json()["error"]

    def test_jwks_db_error_handling(self, client):
        """JWKS returns 500 when a sqlite3.Error occurs."""
        with patch(
            "project2.get_jwks",
            side_effect=sqlite3.OperationalError("corrupt"),
        ):
            res = client.get("/.well-known/jwks.json")
            assert res.status_code == 500
            assert "Database error retrieving JWKS" in res.get_json()["error"]


class TestAuthEndpoint:
    """Tests for POST /auth endpoint."""

    def test_auth_unexpired_key_default(self, client):
        """POST /auth should issue a valid JWT with kid and unexpired exp."""
        res = client.post("/auth")
        assert res.status_code == 200
        assert res.content_type == "application/jwt"

        token = res.get_data(as_text=True)
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "RS256"
        assert "kid" in header

        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload["sub"] == "userABC"
        assert payload["exp"] > datetime.now(timezone.utc).timestamp()

    def test_auth_expired_key_param(self, client):
        """POST /auth?expired=true should issue JWT with expired key."""
        res = client.post("/auth?expired=true")
        assert res.status_code == 200

        token = res.get_data(as_text=True)
        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload["exp"] <= datetime.now(timezone.utc).timestamp()

    def test_auth_expired_param_variants(self, client):
        """POST /auth with ?expired=1 and ?expired should also use expired."""
        res1 = client.post("/auth?expired=1")
        assert res1.status_code == 200
        token1 = res1.get_data(as_text=True)
        p1 = jwt.decode(token1, options={"verify_signature": False})
        assert p1["exp"] <= datetime.now(timezone.utc).timestamp()

        res2 = client.post("/auth?expired")
        assert res2.status_code == 200
        token2 = res2.get_data(as_text=True)
        p2 = jwt.decode(token2, options={"verify_signature": False})
        assert p2["exp"] <= datetime.now(timezone.utc).timestamp()

    def test_auth_with_json_body(self, client):
        """POST /auth accepts JSON payload with username/password."""
        res = client.post(
            "/auth",
            json={"username": "customUser", "password": "password123"},
        )
        assert res.status_code == 200
        token = res.get_data(as_text=True)
        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload["sub"] == "customUser"

    def test_auth_with_basic_auth(self, client):
        """POST /auth accepts HTTP Basic Authentication."""
        creds = base64.b64encode(b"basicUser:secret").decode("utf-8")
        res = client.post(
            "/auth",
            headers={"Authorization": f"Basic {creds}"},
        )
        assert res.status_code == 200
        token = res.get_data(as_text=True)
        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload["sub"] == "basicUser"

    def test_auth_no_key_found_returns_500(self, client):
        """POST /auth returns 500 when no key exists for signing."""
        with patch("project2.get_unexpired_key", return_value=None):
            res = client.post("/auth")
            assert res.status_code == 500
            assert "No unexpired key found" in res.get_json()["error"]

        with patch("project2.get_expired_key", return_value=None):
            res = client.post("/auth?expired=true")
            assert res.status_code == 500
            assert "No expired key found" in res.get_json()["error"]

    def test_auth_key_deserialization_error_returns_500(self, client):
        """POST /auth returns 500 if key deserialization fails."""
        with patch(
            "project2.deserialize_private_key",
            side_effect=ValueError("bad key data"),
        ):
            res = client.post("/auth")
            assert res.status_code == 500
            assert "Key deserialization failed" in res.get_json()["error"]

    def test_auth_jwt_encode_error_returns_500(self, client):
        """POST /auth returns 500 if jwt.encode raises PyJWTError."""
        with patch("jwt.encode", side_effect=jwt.PyJWTError("encoding issue")):
            res = client.post("/auth")
            assert res.status_code == 500
            assert "JWT encoding failed" in res.get_json()["error"]

    def test_auth_generic_error_returns_500(self, client):
        """POST /auth returns 500 on unexpected exception during signing."""
        with patch("jwt.encode", side_effect=RuntimeError("unexpected fail")):
            res = client.post("/auth")
            assert res.status_code == 500
            assert "Internal server error" in res.get_json()["error"]

    def test_auth_db_error_returns_500(self, client):
        """POST /auth returns 500 when database query raises sqlite3.Error."""
        with patch(
            "project2.get_unexpired_key",
            side_effect=sqlite3.OperationalError("db locked"),
        ):
            res = client.post("/auth")
            assert res.status_code == 500
            assert "Database error" in res.get_json()["error"]


class TestRestCompliance:
    """Tests for HTTP method restrictions and 405 Method Not Allowed."""

    def test_jwks_unsupported_methods(self, client):
        """Unsupported methods on JWKS endpoint should return 405."""
        assert client.post("/.well-known/jwks.json").status_code == 405
        assert client.put("/.well-known/jwks.json").status_code == 405
        assert client.delete("/.well-known/jwks.json").status_code == 405
        assert client.patch("/.well-known/jwks.json").status_code == 405

        assert client.post("/jwks").status_code == 405
        assert client.put("/jwks").status_code == 405
        assert client.delete("/jwks").status_code == 405

    def test_auth_unsupported_methods(self, client):
        """Unsupported methods on /auth endpoint should return 405."""
        assert client.get("/auth").status_code == 405
        assert client.put("/auth").status_code == 405
        assert client.delete("/auth").status_code == 405
        assert client.patch("/auth").status_code == 405


class TestAppMain:
    """Test setup_app and main block invocations."""

    def test_setup_app(self, tmp_path):
        """setup_app creates DB and initial keys."""
        db_file = str(tmp_path / "standalone.db")
        project2.setup_app(db_file)
        assert os.path.exists(db_file)
        conn = sqlite3.connect(db_file)
        rows = conn.execute("SELECT count(*) FROM keys").fetchone()[0]
        conn.close()
        assert rows >= 2

    def test_main_block_execution(self, monkeypatch):
        """Test running project2.py as main script invokes app.run."""
        import runpy

        with patch("flask.Flask.run") as mock_run:
            monkeypatch.setenv("PORT", "8080")
            runpy.run_path("project2.py", run_name="__main__")
            assert mock_run.called
