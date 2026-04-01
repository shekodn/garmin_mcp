"""Unit tests for the browser-backed Garmin session client."""

import hashlib
from pathlib import Path

import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from garmin_mcp.browser_session import (
    CHROME_IV,
    BrowserSessionClient,
    build_cookie_jar,
    decrypt_linux_cookie_value,
    derive_linux_cookie_key,
    extract_csrf_token,
)


def _encrypt_linux_cookie(host_key: str, value: str, secret: str) -> bytes:
    plaintext = hashlib.sha256(host_key.encode("utf-8")).digest() + value.encode(
        "utf-8"
    )
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(derive_linux_cookie_key(secret)),
        modes.CBC(CHROME_IV),
    )
    encryptor = cipher.encryptor()
    return b"v10" + encryptor.update(padded) + encryptor.finalize()


def test_decrypt_linux_cookie_value_round_trip():
    host_key = ".connect.garmin.com"
    cookie_value = "garmin-session-cookie"
    secret = "unit-test-secret"
    encrypted = _encrypt_linux_cookie(host_key, cookie_value, secret)

    assert decrypt_linux_cookie_value(host_key, encrypted, secret) == cookie_value


def test_build_cookie_jar_uses_first_working_secret():
    host_key = ".connect.garmin.com"
    secret = "correct-secret"
    encrypted = _encrypt_linux_cookie(host_key, "session-value", secret)
    rows = [
        {
            "host_key": host_key,
            "name": "session",
            "path": "/",
            "value": "",
            "encrypted_value": encrypted,
            "is_secure": 1,
            "is_httponly": 1,
        }
    ]

    jar = build_cookie_jar(rows, ["wrong-secret", secret])

    assert jar.get("session", domain=host_key, path="/") == "session-value"


def test_extract_csrf_token():
    html = '<meta name="csrf-token" content="csrf-value-123">'
    assert extract_csrf_token(html) == "csrf-value-123"


def test_browser_session_client_routes_connectapi_to_gc_api():
    class RecordingSession(requests.Session):
        def __init__(self):
            super().__init__()
            self.calls = []

        def request(self, method, url, headers=None, timeout=None, **kwargs):
            self.calls.append(
                {
                    "method": method,
                    "url": url,
                    "headers": headers or {},
                    "timeout": timeout,
                    "kwargs": kwargs,
                }
            )
            response = requests.Response()
            response.status_code = 200
            response.url = url
            response._content = b'{"ok": true}'
            return response

    session = RecordingSession()
    client = BrowserSessionClient(
        session=session,
        browser_name="chromium",
        profile_dir=Path("/tmp"),
    )
    client.csrf_token = "csrf-token"

    response = client.request("GET", "connectapi", "/userprofile-service/socialProfile")

    assert response.status_code == 200
    assert session.calls[0]["url"] == (
        "https://connect.garmin.com/gc-api/userprofile-service/socialProfile"
    )
    assert session.calls[0]["headers"]["Connect-Csrf-Token"] == "csrf-token"
