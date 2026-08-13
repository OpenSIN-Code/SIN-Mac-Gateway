from __future__ import annotations

import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    RegistrationError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl


CLAUDE_REDIRECT_URIS = (
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
)


class SQLiteOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    """Single-operator OAuth provider with persistent, revocable opaque tokens."""

    def __init__(self, *, db_path: str, client_id: str, client_secret: str) -> None:
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.client = OAuthClientInformationFull(
            client_id=client_id,
            client_secret=client_secret,
            client_name="Claude",
            redirect_uris=[AnyUrl(uri) for uri in CLAUDE_REDIRECT_URIS],
            token_endpoint_auth_method="client_secret_post",
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope="mac",
            client_secret_expires_at=0,
        )
        self._init_db()

    @contextmanager
    def _connect(self):
        """Open one SQLite connection and always release its descriptors.

        sqlite3.Connection.__exit__ only commits/rolls back; it does not close
        the connection.  The OAuth verifier runs for every MCP request, so
        leaving connections open eventually exhausts the process file-descriptor
        limit (and WAL/SHM handles).
        """
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _init_db(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS auth_codes (
                    code TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    code_challenge TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    redirect_uri_explicit INTEGER NOT NULL,
                    resource TEXT,
                    subject TEXT
                );
                CREATE TABLE IF NOT EXISTS access_tokens (
                    token TEXT PRIMARY KEY,
                    family TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    resource TEXT,
                    subject TEXT
                );
                CREATE TABLE IF NOT EXISTS refresh_tokens (
                    token TEXT PRIMARY KEY,
                    family TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    subject TEXT
                );
                """
            )
        try:
            os.chmod(self.db_path, 0o600)
        except FileNotFoundError:
            pass

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.client if client_id == self.client.client_id else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        raise RegistrationError("invalid_client_metadata", "Dynamic client registration is disabled")

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        redirect_uri = str(params.redirect_uri)
        if redirect_uri not in CLAUDE_REDIRECT_URIS:
            raise ValueError("redirect URI is not an allowed Claude callback")
        code = secrets.token_urlsafe(32)
        with self._connect() as db:
            db.execute(
                "INSERT INTO auth_codes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    code,
                    client.client_id,
                    json.dumps(params.scopes or ["mac"]),
                    time.time() + 300,
                    params.code_challenge,
                    redirect_uri,
                    1 if params.redirect_uri_provided_explicitly else 0,
                    params.resource,
                    "operator",
                ),
            )
        return construct_redirect_uri(redirect_uri, code=code, state=params.state)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM auth_codes WHERE code = ? AND client_id = ?",
                (authorization_code, client.client_id),
            ).fetchone()
        if row is None:
            return None
        return AuthorizationCode(
            code=row["code"],
            client_id=row["client_id"],
            scopes=json.loads(row["scopes"]),
            expires_at=row["expires_at"],
            code_challenge=row["code_challenge"],
            redirect_uri=AnyUrl(row["redirect_uri"]),
            redirect_uri_provided_explicitly=bool(row["redirect_uri_explicit"]),
            resource=row["resource"],
            subject=row["subject"],
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        now = int(time.time())
        family = secrets.token_urlsafe(24)
        access = secrets.token_urlsafe(48)
        refresh = secrets.token_urlsafe(48)
        with self._connect() as db:
            deleted = db.execute(
                "DELETE FROM auth_codes WHERE code = ? AND client_id = ?",
                (authorization_code.code, client.client_id),
            ).rowcount
            if deleted != 1:
                raise ValueError("authorization code already consumed")
            db.execute(
                "INSERT INTO access_tokens VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    access,
                    family,
                    client.client_id,
                    json.dumps(authorization_code.scopes),
                    now + 3600,
                    authorization_code.resource,
                    authorization_code.subject,
                ),
            )
            db.execute(
                "INSERT INTO refresh_tokens VALUES (?, ?, ?, ?, ?, ?)",
                (
                    refresh,
                    family,
                    client.client_id,
                    json.dumps(authorization_code.scopes),
                    now + 30 * 24 * 3600,
                    authorization_code.subject,
                ),
            )
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=3600,
            scope=" ".join(authorization_code.scopes),
            refresh_token=refresh,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM refresh_tokens WHERE token = ? AND client_id = ?",
                (refresh_token, client.client_id),
            ).fetchone()
        if row is None or row["expires_at"] <= int(time.time()):
            return None
        return RefreshToken(
            token=row["token"],
            client_id=row["client_id"],
            scopes=json.loads(row["scopes"]),
            expires_at=row["expires_at"],
            subject=row["subject"],
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        now = int(time.time())
        access = secrets.token_urlsafe(48)
        new_refresh = secrets.token_urlsafe(48)
        with self._connect() as db:
            row = db.execute(
                "SELECT family FROM refresh_tokens WHERE token = ? AND client_id = ?",
                (refresh_token.token, client.client_id),
            ).fetchone()
            if row is None:
                raise ValueError("refresh token already consumed")
            family = row["family"]
            db.execute("DELETE FROM refresh_tokens WHERE token = ?", (refresh_token.token,))
            db.execute(
                "INSERT INTO access_tokens VALUES (?, ?, ?, ?, ?, ?, ?)",
                (access, family, client.client_id, json.dumps(scopes), now + 3600, None, refresh_token.subject),
            )
            db.execute(
                "INSERT INTO refresh_tokens VALUES (?, ?, ?, ?, ?, ?)",
                (new_refresh, family, client.client_id, json.dumps(scopes), now + 30 * 24 * 3600, refresh_token.subject),
            )
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=3600,
            scope=" ".join(scopes),
            refresh_token=new_refresh,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM access_tokens WHERE token = ?", (token,)).fetchone()
        if row is None or row["expires_at"] <= int(time.time()):
            return None
        return AccessToken(
            token=row["token"],
            client_id=row["client_id"],
            scopes=json.loads(row["scopes"]),
            expires_at=row["expires_at"],
            resource=row["resource"],
            subject=row["subject"],
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        table = "access_tokens" if isinstance(token, AccessToken) else "refresh_tokens"
        with self._connect() as db:
            row = db.execute(f"SELECT family FROM {table} WHERE token = ?", (token.token,)).fetchone()
            if row is None:
                return
            family = row["family"]
            db.execute("DELETE FROM access_tokens WHERE family = ?", (family,))
            db.execute("DELETE FROM refresh_tokens WHERE family = ?", (family,))
