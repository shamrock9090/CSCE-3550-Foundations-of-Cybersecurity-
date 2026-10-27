"""Unit and Integration Tests for JWKS Server — Project 3.

Covers:
  - db_manager: AES encryption, all table CRUD, rate limiter
  - key_manager: serialization, JWKS, key retrieval
  - Flask endpoints: /jwks, /auth (normal + expired + rate-limit), /register

Run with:
    NOT_MY_KEY=testsecret venv/bin/pytest test_app.py \
        --cov=. --cov-report=term-missing -p no:warnings -v
"""

import os
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

import pytest
import jwt

# ---------------------------------------------------------------------------
# Ensure NOT_MY_KEY is always set for every test
# ---------------------------------------------------------------------------
os.environ.setdefault("NOT_MY_KEY", "test-aes-key-for-unit-tests")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Redirect DB_FILE to a fresh temp file and re-init for every test."""
    db_path = str(tmp_path / "test_keys.db")
    monkeypatch.setenv("NOT_MY_KEY", "test-aes-key-for-unit-tests")
    monkeypatch.setattr("db_manager.DB_FILE", db_path)
    monkeypatch.setattr("key_manager.db_manager.DB_FILE", db_path)

    import db_manager as dbm
    import key_manager as km

    dbm.initialize_db()
    km.initialize_keys()
    yield db_path


@pytest.fixture
def client(isolated_db, monkeypatch):
    """Flask test client with testing mode enabled."""
    monkeypatch.setattr("main.db_manager.DB_FILE", isolated_db)
    monkeypatch.setattr("main.key_manager.db_manager.DB_FILE", isolated_db)

    import main as m
    # Reset rate-limiter buckets between tests
    m._buckets.clear()
    m.app.config["TESTING"] = True
    with m.app.test_client() as c:
        yield c


# ===========================================================================
# db_manager — AES encryption
# ===========================================================================

class TestAESEncryption:
    """Tests for AES-256 encrypt/decrypt round-trip in db_manager."""

    def test_encrypt_produces_different_bytes(self):
        import db_manager as dbm
        plaintext = b"hello world"
        cipher1 = dbm.encrypt_key(plaintext)
        cipher2 = dbm.encrypt_key(plaintext)
        # Two encryptions of the same plaintext must differ (random IV)
        assert cipher1 != cipher2

    def test_decrypt_roundtrip(self):
        import db_manager as dbm
        plaintext = b"super secret RSA key data"
        ciphertext = dbm.encrypt_key(plaintext)
        assert dbm.decrypt_key(ciphertext) == plaintext

    def test_encrypted_blob_longer_than_plaintext(self):
        import db_manager as dbm
        plaintext = b"x" * 32
        assert len(dbm.encrypt_key(plaintext)) > len(plaintext)

    def test_missing_env_var_raises(self, monkeypatch):
        import db_manager as dbm
        monkeypatch.delenv("NOT_MY_KEY", raising=False)
        with pytest.raises(EnvironmentError, match="NOT_MY_KEY"):
            dbm.encrypt_key(b"data")

    def test_missing_env_var_decrypt_raises(self, monkeypatch):
        import db_manager as dbm
        blob = dbm.encrypt_key(b"data")
        monkeypatch.delenv("NOT_MY_KEY", raising=False)
        with pytest.raises(EnvironmentError):
            dbm.decrypt_key(blob)


# ===========================================================================
# db_manager — keys table
# ===========================================================================

class TestKeysTable:
    """Tests for encrypted key storage and retrieval."""

    def test_initialize_db_creates_all_tables(self, isolated_db):
        import db_manager as dbm
        conn = sqlite3.connect(isolated_db)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        conn.close()
        assert {"keys", "users", "auth_logs"}.issubset(tables)

    def test_save_key_returns_kid(self, isolated_db):
        import db_manager as dbm
        exp = int(datetime.now(timezone.utc).timestamp()) + 3600
        kid = dbm.save_key(b"-----BEGIN PRIVATE KEY-----\nfake\n", exp)
        assert isinstance(kid, int) and kid >= 1

    def test_stored_key_is_encrypted(self, isolated_db):
        import db_manager as dbm
        pem = b"plaintext-pem-data"
        exp = int(datetime.now(timezone.utc).timestamp()) + 3600
        dbm.save_key(pem, exp)
        conn = sqlite3.connect(isolated_db)
        row = conn.execute("SELECT key FROM keys ORDER BY kid DESC LIMIT 1").fetchone()
        conn.close()
        # Raw DB blob must NOT equal the original plaintext
        assert bytes(row[0]) != pem

    def test_get_unexpired_key_decrypted(self, isolated_db):
        import db_manager as dbm
        row = dbm.get_unexpired_key()
        assert row is not None
        kid, pem, exp = row
        assert exp > int(datetime.now(timezone.utc).timestamp())
        assert pem.startswith(b"-----BEGIN")

    def test_get_expired_key_decrypted(self, isolated_db):
        import db_manager as dbm
        row = dbm.get_expired_key()
        assert row is not None
        _, pem, exp = row
        assert exp <= int(datetime.now(timezone.utc).timestamp())
        assert pem.startswith(b"-----BEGIN")

    def test_get_unexpired_key_none_when_absent(self, isolated_db):
        import db_manager as dbm
        conn = sqlite3.connect(isolated_db)
        now_ts = int(datetime.now(timezone.utc).timestamp())
        conn.execute("DELETE FROM keys WHERE exp > ?", (now_ts,))
        conn.commit()
        conn.close()
        assert dbm.get_unexpired_key() is None

    def test_get_expired_key_none_when_absent(self, isolated_db):
        import db_manager as dbm
        conn = sqlite3.connect(isolated_db)
        now_ts = int(datetime.now(timezone.utc).timestamp())
        conn.execute("DELETE FROM keys WHERE exp <= ?", (now_ts,))
        conn.commit()
        conn.close()
        assert dbm.get_expired_key() is None

    def test_get_all_valid_keys_count(self, isolated_db):
        import db_manager as dbm
        rows = dbm.get_all_valid_keys()
        assert len(rows) == 1  # one valid key from initialize_keys()

    def test_get_all_valid_keys_decrypted(self, isolated_db):
        import db_manager as dbm
        for _, pem, _ in dbm.get_all_valid_keys():
            assert pem.startswith(b"-----BEGIN")

    def test_initialize_db_idempotent(self, isolated_db):
        import db_manager as dbm
        dbm.initialize_db()  # second call should be safe
        conn = sqlite3.connect(isolated_db)
        count = conn.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='keys'"
        ).fetchone()[0]
        conn.close()
        assert count == 1


# ===========================================================================
# db_manager — users table
# ===========================================================================

class TestUsersTable:
    """Tests for user creation and lookup."""

    def test_create_user_returns_id(self, isolated_db):
        import db_manager as dbm
        uid = dbm.create_user("alice", "hash123", "alice@example.com")
        assert isinstance(uid, int) and uid >= 1

    def test_get_user_by_username(self, isolated_db):
        import db_manager as dbm
        dbm.create_user("bob", "hashbob", "bob@example.com")
        row = dbm.get_user_by_username("bob")
        assert row is not None
        assert row[1] == "bob"

    def test_get_user_not_found(self, isolated_db):
        import db_manager as dbm
        assert dbm.get_user_by_username("nobody") is None

    def test_duplicate_username_raises(self, isolated_db):
        import db_manager as dbm
        dbm.create_user("dup", "hash", "dup@example.com")
        with pytest.raises(Exception):
            dbm.create_user("dup", "hash2", "dup2@example.com")


# ===========================================================================
# db_manager — auth_logs table
# ===========================================================================

class TestAuthLogsTable:
    """Tests for authentication request logging."""

    def test_log_auth_request_inserts_row(self, isolated_db):
        import db_manager as dbm
        dbm.log_auth_request("127.0.0.1", None)
        conn = sqlite3.connect(isolated_db)
        count = conn.execute("SELECT count(*) FROM auth_logs").fetchone()[0]
        conn.close()
        assert count == 1

    def test_log_auth_request_with_user_id(self, isolated_db):
        import db_manager as dbm
        uid = dbm.create_user("logger", "h", "l@x.com")
        dbm.log_auth_request("10.0.0.1", uid)
        conn = sqlite3.connect(isolated_db)
        row = conn.execute("SELECT request_ip, user_id FROM auth_logs").fetchone()
        conn.close()
        assert row[0] == "10.0.0.1"
        assert row[1] == uid

    def test_log_multiple_requests(self, isolated_db):
        import db_manager as dbm
        for i in range(5):
            dbm.log_auth_request(f"1.2.3.{i}", None)
        conn = sqlite3.connect(isolated_db)
        count = conn.execute("SELECT count(*) FROM auth_logs").fetchone()[0]
        conn.close()
        assert count == 5


# ===========================================================================
# key_manager
# ===========================================================================

class TestKeyManager:
    """Tests for key generation, serialization, and JWKS output."""

    def test_bytes_to_base64url_no_padding(self):
        from key_manager import bytes_to_base64url
        result = bytes_to_base64url(b"hello world")
        assert "=" not in result and "+" not in result and "/" not in result

    def test_int_to_base64url(self):
        from key_manager import int_to_base64url
        assert isinstance(int_to_base64url(65537), str)

    def test_serialize_deserialize_roundtrip(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from key_manager import serialize_private_key, deserialize_private_key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = serialize_private_key(key)
        recovered = deserialize_private_key(pem)
        assert (key.public_key().public_numbers().n ==
                recovered.public_key().public_numbers().n)

    def test_generate_and_store_key(self, isolated_db):
        from key_manager import generate_and_store_key
        kid = generate_and_store_key(datetime.now(timezone.utc) + timedelta(hours=2))
        assert isinstance(kid, int)

    def test_key_row_to_jwk_fields(self, isolated_db):
        import db_manager as dbm
        from key_manager import key_row_to_jwk
        row = dbm.get_unexpired_key()
        jwk = key_row_to_jwk(row)
        for field in ("kty", "alg", "use", "kid", "n", "e"):
            assert field in jwk
        assert jwk["kty"] == "RSA"

    def test_get_jwks_only_valid(self, isolated_db):
        from key_manager import get_jwks
        result = get_jwks()
        assert "keys" in result
        assert len(result["keys"]) == 1

    def test_get_key_for_auth_unexpired(self, isolated_db):
        from key_manager import get_key_for_auth
        _, _, exp = get_key_for_auth(expired=False)
        assert exp > int(datetime.now(timezone.utc).timestamp())

    def test_get_key_for_auth_expired(self, isolated_db):
        from key_manager import get_key_for_auth
        _, _, exp = get_key_for_auth(expired=True)
        assert exp <= int(datetime.now(timezone.utc).timestamp())

    def test_get_key_for_auth_raises_no_unexpired(self, isolated_db):
        import db_manager as dbm
        from key_manager import get_key_for_auth
        conn = sqlite3.connect(isolated_db)
        conn.execute("DELETE FROM keys WHERE exp > ?",
                     (int(datetime.now(timezone.utc).timestamp()),))
        conn.commit()
        conn.close()
        with pytest.raises(ValueError, match="unexpired"):
            get_key_for_auth(expired=False)

    def test_get_key_for_auth_raises_no_expired(self, isolated_db):
        import db_manager as dbm
        from key_manager import get_key_for_auth
        conn = sqlite3.connect(isolated_db)
        conn.execute("DELETE FROM keys WHERE exp <= ?",
                     (int(datetime.now(timezone.utc).timestamp()),))
        conn.commit()
        conn.close()
        with pytest.raises(ValueError, match="expired"):
            get_key_for_auth(expired=True)

    def test_initialize_keys_creates_two_rows(self, isolated_db):
        conn = sqlite3.connect(isolated_db)
        count = conn.execute("SELECT count(*) FROM keys").fetchone()[0]
        conn.close()
        assert count == 2


# ===========================================================================
# Flask — JWKS endpoint
# ===========================================================================

class TestJWKSEndpoint:
    def test_root_get(self, client):
        res = client.get("/")
        assert res.status_code == 200
        assert "keys" in res.get_json()

    def test_well_known_jwks(self, client):
        res = client.get("/.well-known/jwks.json")
        assert res.status_code == 200
        data = res.get_json()
        assert len(data["keys"]) == 1

    def test_jwks_alias(self, client):
        assert client.get("/jwks").status_code == 200

    def test_jwks_key_fields(self, client):
        key = client.get("/.well-known/jwks.json").get_json()["keys"][0]
        for f in ("kty", "alg", "use", "kid", "n", "e"):
            assert f in key

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


# ===========================================================================
# Flask — /auth endpoint
# ===========================================================================

class TestAuthEndpoint:
    def test_auth_returns_200(self, client):
        assert client.post("/auth").status_code == 200

    def test_auth_content_type(self, client):
        assert "application/jwt" in client.post("/auth").content_type

    def test_auth_jwt_header(self, client):
        token = client.post("/auth").get_data(as_text=True)
        h = jwt.get_unverified_header(token)
        assert h["alg"] == "RS256"
        assert "kid" in h

    def test_auth_unexpired_payload(self, client):
        token = client.post("/auth").get_data(as_text=True)
        p = jwt.decode(token, options={"verify_signature": False})
        assert p["exp"] > datetime.now(timezone.utc).timestamp()

    def test_auth_expired_payload(self, client):
        token = client.post("/auth?expired=true").get_data(as_text=True)
        p = jwt.decode(token, options={"verify_signature": False})
        assert p["exp"] <= datetime.now(timezone.utc).timestamp()

    def test_auth_expired_numeric_param(self, client):
        token = client.post("/auth?expired=1").get_data(as_text=True)
        p = jwt.decode(token, options={"verify_signature": False})
        assert p["exp"] <= datetime.now(timezone.utc).timestamp()

    def test_auth_json_body(self, client):
        res = client.post("/auth", json={"username": "userABC", "password": "pw"})
        assert res.status_code == 200
        p = jwt.decode(res.get_data(as_text=True), options={"verify_signature": False})
        assert p["sub"] == "userABC"

    def test_auth_basic_auth(self, client):
        import base64
        creds = base64.b64encode(b"userABC:pw").decode()
        res = client.post("/auth", headers={"Authorization": f"Basic {creds}"})
        assert res.status_code == 200

    def test_auth_logs_request(self, client, isolated_db):
        client.post("/auth")
        conn = sqlite3.connect(isolated_db)
        count = conn.execute("SELECT count(*) FROM auth_logs").fetchone()[0]
        conn.close()
        assert count == 1

    def test_auth_rate_limit(self, client):
        """11th request in quick succession should return 429."""
        import main as m
        m._buckets.clear()
        # Freeze monotonic time so no window resets between requests
        fixed_time = time.monotonic()
        with patch("main.time.monotonic", return_value=fixed_time):
            responses = [client.post("/auth") for _ in range(11)]
        status_codes = [r.status_code for r in responses]
        assert 429 in status_codes

    def test_auth_rate_limit_refills(self, client):
        """After waiting >1s the window resets and allows requests."""
        import main as m
        m._buckets.clear()
        fixed_time = time.monotonic()
        with patch("main.time.monotonic", return_value=fixed_time):
            for _ in range(10):
                client.post("/auth")
        # New window: time advanced by 1.1s → counter resets
        new_time = fixed_time + 1.1
        with patch("main.time.monotonic", return_value=new_time):
            res = client.post("/auth")
        assert res.status_code == 200

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

    def test_auth_no_key_error(self, client):
        with patch("key_manager.get_key_for_auth", side_effect=ValueError("no key")):
            res = client.post("/auth")
            assert res.status_code == 500


# ===========================================================================
# Flask — /register endpoint
# ===========================================================================

class TestRegisterEndpoint:
    def test_register_returns_201(self, client):
        res = client.post("/register",
                          json={"username": "newuser", "email": "new@example.com"})
        assert res.status_code == 201

    def test_register_returns_password(self, client):
        res = client.post("/register",
                          json={"username": "alice", "email": "a@example.com"})
        data = res.get_json()
        assert "password" in data
        # Should be a valid UUIDv4
        import uuid
        parsed = uuid.UUID(data["password"], version=4)
        assert str(parsed) == data["password"]

    def test_register_password_is_unique(self, client):
        r1 = client.post("/register", json={"username": "u1", "email": "u1@x.com"})
        r2 = client.post("/register", json={"username": "u2", "email": "u2@x.com"})
        assert r1.get_json()["password"] != r2.get_json()["password"]

    def test_register_user_stored_in_db(self, client, isolated_db):
        client.post("/register", json={"username": "stored", "email": "s@x.com"})
        conn = sqlite3.connect(isolated_db)
        row = conn.execute(
            "SELECT username FROM users WHERE username = ?", ("stored",)
        ).fetchone()
        conn.close()
        assert row is not None

    def test_register_password_is_hashed(self, client, isolated_db):
        """Password stored in DB must not equal the returned plaintext."""
        res = client.post("/register", json={"username": "hashed", "email": "h@x.com"})
        plain_pw = res.get_json()["password"]
        conn = sqlite3.connect(isolated_db)
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", ("hashed",)
        ).fetchone()
        conn.close()
        assert row[0] != plain_pw
        assert row[0].startswith("$argon2")

    def test_register_duplicate_username_409(self, client):
        client.post("/register", json={"username": "dup", "email": "d1@x.com"})
        res = client.post("/register", json={"username": "dup", "email": "d2@x.com"})
        assert res.status_code == 409

    def test_register_missing_username_400(self, client):
        res = client.post("/register", json={"email": "no@user.com"})
        assert res.status_code == 400

    def test_register_non_json_400(self, client):
        res = client.post("/register", data="not json",
                          content_type="text/plain")
        assert res.status_code == 400

    def test_register_get_not_allowed(self, client):
        assert client.get("/register").status_code == 405

    def test_register_put_not_allowed(self, client):
        assert client.put("/register").status_code == 405
