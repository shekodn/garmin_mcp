"""Use a logged-in Chromium/Chrome session for Garmin Connect DI auth."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from garth.exc import GarthHTTPError
from garth.http import Client
from garminconnect import Garmin, GarminConnectAuthenticationError
from requests import HTTPError, Response, Session


CHROME_SALT = b"saltysalt"
CHROME_IV = b" " * 16
DEFAULT_ACCEPT_LANGUAGE = "en-US,en;q=0.9"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)
CONNECT_APP_URL = "https://connect.garmin.com/app/"
CONNECT_API_BASE_URL = "https://connect.garmin.com/gc-api/"
CSRF_PATTERN = re.compile(
    r'<meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


class BrowserSessionError(RuntimeError):
    """Base error for browser-backed Garmin sessions."""


class BrowserProfileNotFoundError(BrowserSessionError):
    """Raised when no suitable browser profile can be found."""


class BrowserSessionAuthenticationError(BrowserSessionError):
    """Raised when the browser profile is present but not logged in."""


@dataclass(frozen=True)
class BrowserProfile:
    """Local browser profile that contains Garmin cookies."""

    browser_name: str
    profile_dir: Path
    cookies_path: Path
    secret_app: str


@dataclass(frozen=True)
class BrowserInstallation:
    """Known browser installation layout on Linux."""

    browser_name: str
    config_root: Path
    secret_app: str


KNOWN_BROWSERS = (
    BrowserInstallation(
        browser_name="chromium",
        config_root=Path("~/.config/chromium").expanduser(),
        secret_app="chromium",
    ),
    BrowserInstallation(
        browser_name="google-chrome",
        config_root=Path("~/.config/google-chrome").expanduser(),
        secret_app="chrome",
    ),
    BrowserInstallation(
        browser_name="google-chrome-beta",
        config_root=Path("~/.config/google-chrome-beta").expanduser(),
        secret_app="chrome",
    ),
    BrowserInstallation(
        browser_name="google-chrome-unstable",
        config_root=Path("~/.config/google-chrome-unstable").expanduser(),
        secret_app="chrome",
    ),
)


def _copy_sqlite_database(db_path: Path) -> tuple[tempfile.TemporaryDirectory, Path]:
    tmpdir = tempfile.TemporaryDirectory(prefix="garmin-mcp-sqlite-")
    copied_db_path = Path(tmpdir.name) / db_path.name
    shutil.copy2(db_path, copied_db_path)

    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{db_path}{suffix}")
        if sidecar.exists():
            shutil.copy2(sidecar, Path(f"{copied_db_path}{suffix}"))

    return tmpdir, copied_db_path


def _query_sqlite(db_path: Path, query: str) -> list[sqlite3.Row]:
    tmpdir, copied_db_path = _copy_sqlite_database(db_path)
    try:
        conn = sqlite3.connect(copied_db_path)
        conn.row_factory = sqlite3.Row
        try:
            return list(conn.execute(query))
        finally:
            conn.close()
    finally:
        tmpdir.cleanup()


def _iter_profile_dirs(config_root: Path) -> list[Path]:
    profiles = []

    default_profile = config_root / "Default"
    if default_profile.is_dir():
        profiles.append(default_profile)

    profiles.extend(
        profile
        for profile in sorted(config_root.glob("Profile *"))
        if profile.is_dir()
    )
    return profiles


def _cookie_score(cookies_path: Path) -> tuple[int, int]:
    rows = _query_sqlite(
        cookies_path,
        """
        SELECT
            COUNT(*) AS cookie_count,
            COALESCE(MAX(last_access_utc), 0) AS last_access_utc
        FROM cookies
        WHERE host_key LIKE '%garmin.com'
        """,
    )
    if not rows:
        return (0, 0)

    row = rows[0]
    return int(row["cookie_count"] or 0), int(row["last_access_utc"] or 0)


def discover_browser_profile() -> BrowserProfile:
    """Find a browser profile that already has Garmin cookies."""
    profile_override = os.getenv("GARMIN_BROWSER_PROFILE_DIR")
    if profile_override:
        profile_dir = Path(profile_override).expanduser().resolve()
        cookies_path = profile_dir / "Cookies"
        if not cookies_path.exists():
            raise BrowserProfileNotFoundError(
                f"Configured browser profile '{profile_dir}' does not contain a Cookies database."
            )
        secret_app = os.getenv("GARMIN_BROWSER_SECRET_APP", "chromium")
        return BrowserProfile(
            browser_name=profile_dir.parent.name.lower(),
            profile_dir=profile_dir,
            cookies_path=cookies_path,
            secret_app=secret_app,
        )

    best_match: BrowserProfile | None = None
    best_score = (0, 0)

    for browser in KNOWN_BROWSERS:
        if not browser.config_root.exists():
            continue

        for profile_dir in _iter_profile_dirs(browser.config_root):
            cookies_path = profile_dir / "Cookies"
            if not cookies_path.exists():
                continue

            score = _cookie_score(cookies_path)
            if score > best_score:
                best_score = score
                best_match = BrowserProfile(
                    browser_name=browser.browser_name,
                    profile_dir=profile_dir,
                    cookies_path=cookies_path,
                    secret_app=browser.secret_app,
                )

    if best_match is None or best_score[0] == 0:
        raise BrowserProfileNotFoundError(
            "No Chromium/Chrome profile with Garmin cookies was found."
        )

    return best_match


def _get_secret_tool_value(secret_app: str) -> str | None:
    try:
        result = subprocess.run(
            ["secret-tool", "lookup", "application", secret_app],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return None

    if result.returncode != 0:
        return None

    secret = result.stdout.strip()
    return secret or None


def _secret_candidates(secret_app: str) -> list[str]:
    secrets: list[str] = []
    looked_up_secret = _get_secret_tool_value(secret_app)
    if looked_up_secret:
        secrets.append(looked_up_secret)

    # Linux Chromium may still use the historical fallback when keyring
    # integration is unavailable.
    secrets.append("peanuts")

    deduped: list[str] = []
    for secret in secrets:
        if secret not in deduped:
            deduped.append(secret)
    return deduped


def derive_linux_cookie_key(secret: str) -> bytes:
    """Derive Chromium's Linux cookie key from the safe-storage secret."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=16,
        salt=CHROME_SALT,
        iterations=1,
    )
    return kdf.derive(secret.encode("utf-8"))


def decrypt_linux_cookie_value(
    host_key: str,
    encrypted_value: bytes,
    secret: str,
) -> str:
    """Decrypt a Linux Chromium cookie value."""
    if not encrypted_value:
        return ""

    if encrypted_value.startswith((b"v10", b"v11")):
        payload = encrypted_value[3:]
    else:
        try:
            return encrypted_value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BrowserSessionError(
                f"Unsupported cookie format for host '{host_key}'."
            ) from exc

    cipher = Cipher(
        algorithms.AES(derive_linux_cookie_key(secret)),
        modes.CBC(CHROME_IV),
    )
    decryptor = cipher.decryptor()
    padded = decryptor.update(payload) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    domain_digest = hashlib.sha256(host_key.encode("utf-8")).digest()
    if plaintext.startswith(domain_digest):
        plaintext = plaintext[len(domain_digest) :]

    return plaintext.decode("utf-8")


def _load_cookie_rows(cookies_path: Path) -> list[sqlite3.Row]:
    rows = _query_sqlite(
        cookies_path,
        """
        SELECT
            host_key,
            name,
            path,
            value,
            encrypted_value,
            is_secure,
            is_httponly
        FROM cookies
        WHERE host_key LIKE '%garmin.com'
        ORDER BY host_key, name
        """,
    )
    if not rows:
        raise BrowserSessionAuthenticationError(
            f"No Garmin cookies were found in '{cookies_path.parent}'."
        )
    return rows


def build_cookie_jar(
    cookie_rows: list[sqlite3.Row],
    secret_candidates: list[str],
) -> requests.cookies.RequestsCookieJar:
    """Build a requests cookie jar from Chromium cookie rows."""
    last_error: Exception | None = None

    for secret in secret_candidates:
        jar = requests.cookies.RequestsCookieJar()
        try:
            for row in cookie_rows:
                host_key = str(row["host_key"])
                name = str(row["name"])
                path = str(row["path"] or "/")
                value = str(row["value"] or "")
                encrypted_value = bytes(row["encrypted_value"] or b"")

                if not value:
                    value = decrypt_linux_cookie_value(host_key, encrypted_value, secret)

                jar.set_cookie(
                    requests.cookies.create_cookie(
                        name=name,
                        value=value,
                        domain=host_key,
                        path=path,
                        secure=bool(row["is_secure"]),
                        rest={"HttpOnly": bool(row["is_httponly"])},
                    )
                )
            return jar
        except Exception as exc:  # pragma: no cover - exercised by candidate fallback
            last_error = exc

    raise BrowserSessionError(
        f"Failed to decrypt Garmin cookies from the browser profile: {last_error}"
    )


def extract_csrf_token(html: str) -> str:
    """Extract the Garmin Connect CSRF token from the signed-in app shell."""
    match = CSRF_PATTERN.search(html)
    if not match:
        raise BrowserSessionAuthenticationError(
            "Garmin Connect app shell did not expose a CSRF token."
        )
    return match.group(1)


class BrowserSessionClient(Client):
    """Minimal garth-compatible client backed by a browser DI session."""

    def __init__(
        self,
        *,
        session: Session | None = None,
        browser_name: str,
        profile_dir: Path,
    ) -> None:
        super().__init__(session=session, domain="garmin.com")
        self.browser_name = browser_name
        self.profile_dir = profile_dir
        self.csrf_token = ""
        self.last_resp: Response | None = None
        self.sess.headers.update(
            {
                "User-Agent": DEFAULT_USER_AGENT,
                "Accept-Language": DEFAULT_ACCEPT_LANGUAGE,
            }
        )

    def refresh_csrf_token(self) -> str:
        """Refresh the DI session CSRF token from the signed-in Garmin shell."""
        response = self.sess.get(
            CONNECT_APP_URL,
            headers={
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,"
                    "image/avif,image/webp,*/*;q=0.8"
                ),
                "Referer": "https://connect.garmin.com/",
            },
            timeout=self.timeout,
        )
        self.last_resp = response
        response.raise_for_status()

        if "sso.garmin.com" in response.url or "sign-in" in response.url:
            raise BrowserSessionAuthenticationError(
                "Browser profile is not signed in to Garmin Connect."
            )

        self.csrf_token = extract_csrf_token(response.text)
        return self.csrf_token

    def bootstrap(self) -> None:
        """Validate the session and warm the cached Garmin profile."""
        self.refresh_csrf_token()
        self._user_profile = self.connectapi("/userprofile-service/socialProfile")
        if not isinstance(self._user_profile, dict) or not self._user_profile.get(
            "displayName"
        ):
            raise BrowserSessionAuthenticationError(
                "Signed-in browser session did not return a valid Garmin profile."
            )

    def _build_url(self, subdomain: str, path: str, api: bool) -> str:
        if subdomain == "connectapi" or api:
            return urljoin(CONNECT_API_BASE_URL, path.lstrip("/"))
        return urljoin(f"https://{subdomain}.{self.domain}/", path.lstrip("/"))

    def _request_headers(
        self,
        headers: dict[str, str] | None,
        *,
        api_request: bool,
        referrer: str | bool,
    ) -> dict[str, str]:
        merged = dict(headers or {})

        if referrer is True and self.last_resp is not None:
            merged["referer"] = self.last_resp.url

        if api_request:
            merged = {
                "Accept": "application/json, text/plain, */*",
                "Origin": "https://connect.garmin.com",
                "Referer": CONNECT_APP_URL,
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "Priority": "u=1, i",
                **merged,
            }
            merged["Connect-Csrf-Token"] = self.csrf_token

        return merged

    def request(
        self,
        method: str,
        subdomain: str,
        path: str,
        /,
        api: bool = False,
        referrer: str | bool = False,
        headers: dict | None = None,
        **kwargs: Any,
    ) -> Response:
        api_request = subdomain == "connectapi" or api
        if api_request and not self.csrf_token:
            self.refresh_csrf_token()

        url = self._build_url(subdomain, path, api_request)
        request_headers = self._request_headers(
            headers, api_request=api_request, referrer=referrer
        )

        self.last_resp = self.sess.request(
            method,
            url,
            headers=request_headers,
            timeout=self.timeout,
            **kwargs,
        )

        if self.last_resp.status_code == 403 and api_request:
            self.refresh_csrf_token()
            request_headers["Connect-Csrf-Token"] = self.csrf_token
            self.last_resp = self.sess.request(
                method,
                url,
                headers=request_headers,
                timeout=self.timeout,
                **kwargs,
            )

        try:
            self.last_resp.raise_for_status()
        except HTTPError as exc:
            raise GarthHTTPError(msg="Error in request", error=exc) from exc

        return self.last_resp


def create_browser_garmin_client() -> Garmin:
    """Create a garminconnect client from an authenticated browser profile."""
    profile = discover_browser_profile()
    cookie_rows = _load_cookie_rows(profile.cookies_path)
    cookie_jar = build_cookie_jar(cookie_rows, _secret_candidates(profile.secret_app))

    session = requests.Session()
    session.cookies = cookie_jar

    browser_client = BrowserSessionClient(
        session=session,
        browser_name=profile.browser_name,
        profile_dir=profile.profile_dir,
    )
    browser_client.bootstrap()

    garmin = Garmin()
    garmin.garth = browser_client

    user_profile = browser_client.user_profile
    if not isinstance(user_profile, dict):
        raise BrowserSessionAuthenticationError(
            "Browser session did not return a Garmin user profile."
        )

    garmin.display_name = user_profile.get("displayName")
    garmin.full_name = user_profile.get("fullName")

    try:
        user_settings = browser_client.connectapi(
            "/userprofile-service/userprofile/user-settings"
        )
    except GarthHTTPError as exc:
        raise GarminConnectAuthenticationError(
            f"Browser session could not fetch user settings: {exc}"
        ) from exc

    if isinstance(user_settings, dict):
        garmin.unit_system = (
            user_settings.get("userData", {}) or {}
        ).get("measurementSystem")

    if not garmin.display_name:
        raise BrowserSessionAuthenticationError(
            "Browser session did not expose Garmin displayName."
        )

    return garmin
