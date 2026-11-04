"""Unit and Integration Tests for JWKS Server (Project 3).

Tests verify:
  - AES-256 encryption and decryption of private keys (NOT_MY_KEY).
  - SQLite database management (keys, users, auth_logs tables).
  - User registration (POST /register) with UUIDv4 passwords and Argon2.
  - Authentication request logging to auth_logs.
  - Sliding-window rate limiter (10 req/s, returns HTTP 429).
  - Public JWKS endpoint and JWT signing with kid in header.
"""

import base64
import sqlite3
import time
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import jwt
import pytest

import project3


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """Provide an isolated temporary SQLite database for each test."""
    db_file = str(tmp_path / "test_project3.db")
    monkeypatch.setattr(project3, "DB_FILE", db_file)
    monkeypatch.setenv("NOT_MY_KEY", "super_secret_test_key_32_bytes_!")
    project3.reset_rate_limiter()
    project3.init_db(db_file)
    project3.seed_initial_keys(db_file)
    yield db_file


@pytest.fixture
def client(temp_db):
    """Provide a Flask test client configured for the isolated database."""
    project3.app.config["TESTING"] = True
    with project3.app.test_client() as test_client:
        yield test_client


class TestDatabaseAndEncryption:
    """Tests for SQLite database tables and AES encryption."""

    def test_init_db_creates_all_tables(self, temp_db):
        """init_db should create keys, users, and auth_logs tables."""
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = {row[0] for row in cursor.fetchall()}
        conn.close()
        assert "keys" in tables
        assert "users" in tables
        assert "auth_logs" in tables

    def test_get_aes_key_variants(self, monkeypatch):
        """get_aes_key supports exact byte lengths and derives from strings."""
        monkeypatch.setenv("NOT_MY_KEY", "1234567890123456")  # 16 bytes
        assert len(project3.get_aes_key()) == 16

        monkeypatch.setenv(
            "NOT_MY_KEY", "12345678901234567890123456789012"
        )  # 32 bytes
        assert len(project3.get_aes_key()) == 32

        monkeypatch.setenv("NOT_MY_KEY", "arbitrary_passphrase_string")
        assert len(project3.get_aes_key()) == 32

        monkeypatch.delenv("NOT_MY_KEY", raising=False)
        with pytest.raises(EnvironmentError):
            project3.get_aes_key()

    def test_aes_encrypt_decrypt_roundtrip(self, monkeypatch):
        """encrypt_key and decrypt_key should preserve original plaintext."""
        monkeypatch.setenv("NOT_MY_KEY", "my_secret_key_32_bytes_testing!")
        plaintext = b"This is a secret private key string for testing AES."
        ciphertext = project3.encrypt_key(plaintext)
        assert ciphertext != plaintext
        assert len(ciphertext) > len(plaintext)  # IV (16) + padded ciphertext

        decrypted = project3.decrypt_key(ciphertext)
        assert decrypted == plaintext

    def test_save_key_encrypts_in_db(self, temp_db):
        """Saved private keys must be stored encrypted in the database."""
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT key FROM keys LIMIT 1")
        blob = cursor.fetchone()[0]
        conn.close()

        # The blob should NOT contain the plaintext PEM header
        assert b"BEGIN RSA PRIVATE KEY" not in blob
        assert b"BEGIN PRIVATE KEY" not in blob

        # Decrypting the blob must yield the valid PEM
        decrypted = project3.decrypt_key(blob)
        assert b"BEGIN RSA PRIVATE KEY" in decrypted

    def test_get_unexpired_and_expired_keys(self, temp_db):
        """Key retrieval functions should return decrypted rows."""
        unexpired = project3.get_unexpired_key(db_path=temp_db)
        assert unexpired is not None
        assert unexpired[2] > int(datetime.now(timezone.utc).timestamp())
        assert b"BEGIN RSA PRIVATE KEY" in unexpired[1]

        expired = project3.get_expired_key(db_path=temp_db)
        assert expired is not None
        assert expired[2] <= int(datetime.now(timezone.utc).timestamp())
        assert b"BEGIN RSA PRIVATE KEY" in expired[1]

    def test_get_keys_none_when_empty(self, temp_db):
        """Key queries should return None when matching rows are deleted."""
        conn = sqlite3.connect(temp_db)
        conn.execute("DELETE FROM keys")
        conn.commit()
        conn.close()

        assert project3.get_unexpired_key(db_path=temp_db) is None
        assert project3.get_expired_key(db_path=temp_db) is None
        assert project3.get_all_valid_keys(db_path=temp_db) == []

    def test_user_creation_and_lookup(self, temp_db):
        """create_user and get_user_by_username should manage user rows."""
        uid = project3.create_user(
            username="alice",
            password_hash="argon2_hashed_secret",
            email="alice@example.com",
            db_path=temp_db,
        )
        assert isinstance(uid, int)

        user = project3.get_user_by_username("alice", db_path=temp_db)
        assert user is not None
        assert user[1] == "alice"
        assert user[2] == "argon2_hashed_secret"
        assert user[3] == "alice@example.com"

        assert project3.get_user_by_username("nonexistent", temp_db) is None

    def test_user_creation_unique_constraints(self, temp_db):
        """Duplicate username or email should raise sqlite3.IntegrityError."""
        project3.create_user(
            username="bob",
            password_hash="hash1",
            email="bob@example.com",
            db_path=temp_db,
        )
        with pytest.raises(sqlite3.IntegrityError):
            project3.create_user(
                username="bob",
                password_hash="hash2",
                email="bob2@example.com",
                db_path=temp_db,
            )

    def test_log_auth_request(self, temp_db):
        """log_auth_request should record entry into auth_logs table."""
        log_id = project3.log_auth_request(
            request_ip="192.168.1.50",
            user_id=None,
            db_path=temp_db,
        )
        assert isinstance(log_id, int)

        conn = sqlite3.connect(temp_db)
        row = conn.execute(
            "SELECT request_ip, user_id FROM auth_logs WHERE id = ?",
            (log_id,),
        ).fetchone()
        conn.close()
        assert row[0] == "192.168.1.50"
        assert row[1] is None

    def test_database_error_handling(self, temp_db):
        """Database helper functions should raise sqlite3.Error on failure."""
        with patch("sqlite3.connect") as mock_connect:
            mock_conn = MagicMock()
            mock_conn.execute.side_effect = sqlite3.OperationalError(
                "disk fail"
            )
            mock_connect.return_value = mock_conn

            with pytest.raises(sqlite3.Error):
                project3.init_db(temp_db)

            with pytest.raises(sqlite3.Error):
                project3.save_key(b"key", 12345, db_path=temp_db)

            with pytest.raises(sqlite3.Error):
                project3.get_unexpired_key(db_path=temp_db)

            with pytest.raises(sqlite3.Error):
                project3.get_expired_key(db_path=temp_db)

            with pytest.raises(sqlite3.Error):
                project3.get_all_valid_keys(db_path=temp_db)

            with pytest.raises(sqlite3.Error):
                project3.create_user("u", "p", db_path=temp_db)

            with pytest.raises(sqlite3.Error):
                project3.get_user_by_username("u", db_path=temp_db)

            with pytest.raises(sqlite3.Error):
                project3.log_auth_request("ip", 1, db_path=temp_db)


class TestUserRegistration:
    """Tests for POST /register endpoint."""

    def test_register_success(self, client):
        """POST /register should return 201 with generated UUID password."""
        res = client.post(
            "/register",
            json={"username": "newUser", "email": "new@example.com"},
        )
        assert res.status_code == 201
        data = res.get_json()
        assert "password" in data
        password = data["password"]

        # Verify password hash in DB verifies with Argon2
        user_row = project3.get_user_by_username("newUser")
        assert user_row is not None
        assert project3.password_hasher.verify(user_row[2], password)

    def test_register_non_json_body(self, client):
        """POST /register with non-JSON body returns 400."""
        res = client.post("/register", data="not json")
        assert res.status_code == 400
        assert "Request body must be JSON" in res.get_json()["error"]

    def test_register_missing_username(self, client):
        """POST /register without username returns 400."""
        res = client.post("/register", json={"email": "no_user@example.com"})
        assert res.status_code == 400
        assert "username is required" in res.get_json()["error"]

    def test_register_duplicate_username(self, client):
        """POST /register with existing username returns 409 Conflict."""
        client.post("/register", json={"username": "dupeUser"})
        res = client.post("/register", json={"username": "dupeUser"})
        assert res.status_code == 409
        assert "already exists" in res.get_json()["error"]

    def test_register_db_error(self, client):
        """POST /register handles unexpected database error."""
        with patch(
            "project3.create_user",
            side_effect=sqlite3.OperationalError("db locked"),
        ):
            res = client.post("/register", json={"username": "errorUser"})
            assert res.status_code == 500
            assert "Database registration error" in res.get_json()["error"]


class TestRateLimiterAndAuthLogging:
    """Tests for rate limiting and auth request logging on POST /auth."""

    def test_auth_success_and_logs(self, client, temp_db):
        """POST /auth issues JWT and logs request to auth_logs."""
        # Create user so user_id can be resolved
        client.post("/register", json={"username": "registeredUser"})
        user_row = project3.get_user_by_username("registeredUser")
        user_id = user_row[0]

        res = client.post(
            "/auth",
            json={"username": "registeredUser", "password": "any"},
        )
        assert res.status_code == 200
        assert res.content_type == "application/jwt"

        conn = sqlite3.connect(temp_db)
        log_row = conn.execute(
            "SELECT request_ip, user_id FROM auth_logs "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        conn.close()
        assert log_row is not None
        assert log_row[1] == user_id

    def test_rate_limiter_exceeded_returns_429(self, client):
        """11th request within 1 second should return 429 Too Many Requests."""
        project3.reset_rate_limiter()
        fixed_time = time.time()
        with patch("project3.time.time", return_value=fixed_time):
            responses = [client.post("/auth") for _ in range(11)]
        status_codes = [r.status_code for r in responses]
        assert status_codes.count(200) == 10
        assert status_codes[-1] == 429
        assert "Too Many Requests" in responses[-1].get_json()["error"]

    def test_rate_limiter_window_slides(self, client):
        """Requests after 1 second window should succeed."""
        project3.reset_rate_limiter()
        fixed_time = time.time()
        with patch("project3.time.time", return_value=fixed_time):
            for _ in range(10):
                client.post("/auth")

        # Advance past 1-second window
        with patch("project3.time.time", return_value=fixed_time + 1.1):
            res = client.post("/auth")
            assert res.status_code == 200

    def test_rate_limited_requests_not_logged(self, client, temp_db):
        """Rate-limited (429) requests must not be logged to auth_logs."""
        project3.reset_rate_limiter()
        fixed_time = time.time()
        with patch("project3.time.time", return_value=fixed_time):
            for _ in range(12):
                client.post("/auth")

        conn = sqlite3.connect(temp_db)
        count = conn.execute("SELECT count(*) FROM auth_logs").fetchone()[0]
        conn.close()
        assert count == 10  # Only the 10 succeeding requests logged!

    def test_auth_expired_key(self, client):
        """POST /auth?expired=true issues JWT signed with expired key."""
        res = client.post("/auth?expired=true")
        assert res.status_code == 200
        token = res.get_data(as_text=True)
        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload["exp"] <= datetime.now(timezone.utc).timestamp()

    def test_auth_with_basic_auth(self, client):
        """POST /auth extracts username from Basic Auth."""
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
        """POST /auth returns 500 when no key exists."""
        with patch("project3.get_unexpired_key", return_value=None):
            res = client.post("/auth")
            assert res.status_code == 500
            assert "No unexpired key found" in res.get_json()["error"]

    def test_auth_deserialization_error_returns_500(self, client):
        """POST /auth returns 500 on key deserialization failure."""
        with patch(
            "project3.deserialize_private_key",
            side_effect=ValueError("bad key"),
        ):
            res = client.post("/auth")
            assert res.status_code == 500

    def test_auth_jwt_encode_error_returns_500(self, client):
        """POST /auth returns 500 on jwt.encode failure."""
        with patch("jwt.encode", side_effect=jwt.PyJWTError("encode fail")):
            res = client.post("/auth")
            assert res.status_code == 500

    def test_auth_generic_error_returns_500(self, client):
        """POST /auth returns 500 on unexpected exception."""
        with patch("jwt.encode", side_effect=RuntimeError("unexpected")):
            res = client.post("/auth")
            assert res.status_code == 500

    def test_auth_log_failure_returns_500(self, client):
        """POST /auth returns 500 if logging fails."""
        with patch(
            "project3.log_auth_request",
            side_effect=sqlite3.OperationalError("db error"),
        ):
            res = client.post("/auth")
            assert res.status_code == 500
            assert "Failed to log auth request" in res.get_json()["error"]


class TestJWKSAndREST:
    """Tests for JWKS endpoint and REST compliance."""

    def test_jwks_standard_route(self, client):
        """GET /.well-known/jwks.json returns 200 and JWKS list."""
        res = client.get("/.well-known/jwks.json")
        assert res.status_code == 200
        data = res.get_json()
        assert "keys" in data
        assert len(data["keys"]) >= 1
        key = data["keys"][0]
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert key["use"] == "sig"

    def test_jwks_route_aliases(self, client):
        """GET / and GET /jwks return JWKS."""
        assert client.get("/").status_code == 200
        assert client.get("/jwks").status_code == 200

    def test_jwks_db_error_returns_500(self, client):
        """GET /jwks returns 500 on sqlite3 error."""
        with patch(
            "project3.get_jwks",
            side_effect=sqlite3.OperationalError("corrupted"),
        ):
            res = client.get("/.well-known/jwks.json")
            assert res.status_code == 500

    def test_jwks_generic_error_returns_500(self, client):
        """GET /jwks returns 500 on generic exception."""
        with patch("project3.get_jwks", side_effect=RuntimeError("generic")):
            res = client.get("/.well-known/jwks.json")
            assert res.status_code == 500

    def test_unsupported_methods_return_405(self, client):
        """Endpoints return 405 Method Not Allowed for unsupported methods."""
        assert client.post("/.well-known/jwks.json").status_code == 405
        assert client.put("/.well-known/jwks.json").status_code == 405
        assert client.delete("/.well-known/jwks.json").status_code == 405

        assert client.get("/auth").status_code == 405
        assert client.put("/auth").status_code == 405
        assert client.delete("/auth").status_code == 405

        assert client.get("/register").status_code == 405
        assert client.put("/register").status_code == 405
        assert client.delete("/register").status_code == 405

    def test_main_block_execution(self, monkeypatch):
        """Running project3.py as main script invokes app.run."""
        import runpy

        with patch("flask.Flask.run") as mock_run:
            monkeypatch.setenv("PORT", "8080")
            runpy.run_path("project3.py", run_name="__main__")
            assert mock_run.called
