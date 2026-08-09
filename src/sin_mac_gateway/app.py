from __future__ import annotations

import argparse
import json
import logging
import os
import re
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import mcp.types as types
import uvicorn
from mcp.server.auth.provider import ProviderTokenVerifier
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.lowlevel import Server
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from .backend import BackendError, StdioMCPBackend
from .oauth import SQLiteOAuthProvider

LOG = logging.getLogger("sin_mac_gateway")

_HIGH_CONFIDENCE_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|PRIVATE) PRIVATE KEY-----.*?-----END .*? PRIVATE KEY-----", re.S),
    re.compile(r"\b(?:gh[opsu]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})\b"),
    re.compile(r"(?i)\b(authorization:\s*bearer\s+)[A-Za-z0-9._~+/-]{20,}"),
)

_BLOCKED_COMMAND_MARKERS = (
    "security dump-keychain",
    "security find-generic-password",
    "library/keychains",
    "/.ssh/id_",
    "/.gnupg/",
    "login data",
    "cookies.binarycookies",
)

_SENSITIVE_PATH_ROOTS = (
    Path.home() / ".ssh",
    Path.home() / ".gnupg",
    Path.home() / "Library/Keychains",
    Path.home() / "Library/Application Support/Google/Chrome",
    Path.home() / "Library/Application Support/Chromium",
)
_SENSITIVE_FILENAMES = {".env", ".env.local", "id_rsa", "id_ed25519", "credentials.json"}


def _guard_filesystem(arguments: dict[str, Any]) -> str | None:
    values: list[str] = []
    for key in ("path", "source", "destination"):
        value = arguments.get(key)
        if isinstance(value, str):
            values.append(value)
    paths = arguments.get("paths")
    if isinstance(paths, list):
        values.extend(value for value in paths if isinstance(value, str))
    for value in values:
        candidate = Path(value).expanduser()
        try:
            candidate = candidate.resolve(strict=False)
        except OSError:
            continue
        if candidate.name in _SENSITIVE_FILENAMES:
            return f"blocked sensitive file: {candidate.name}"
        for root in _SENSITIVE_PATH_ROOTS:
            resolved_root = root.resolve(strict=False)
            if candidate == resolved_root or resolved_root in candidate.parents:
                return f"blocked sensitive path: {resolved_root}"
    return None


def _redact_text(text: str) -> str:
    redacted = text
    for pattern in _HIGH_CONFIDENCE_SECRET_PATTERNS:
        if pattern.pattern.lower().startswith("(?i)\\b(authorization"):
            redacted = pattern.sub(r"\1[REDACTED]", redacted)
        else:
            redacted = pattern.sub("[REDACTED_SECRET]", redacted)
    return redacted


def _guard_command(arguments: dict[str, Any]) -> str | None:
    pieces: list[str] = []
    command_line = arguments.get("command_line")
    argv = arguments.get("argv")
    if isinstance(command_line, str):
        pieces.append(command_line)
    if isinstance(argv, list):
        pieces.extend(str(part) for part in argv)
    normalized = " ".join(pieces).lower()
    for marker in _BLOCKED_COMMAND_MARKERS:
        if marker in normalized:
            return f"blocked sensitive command marker: {marker}"
    return None


def _redact_call_result(result: types.CallToolResult) -> types.CallToolResult:
    changed = False
    content: list[types.ContentBlock] = []
    for block in result.content:
        if isinstance(block, types.TextContent):
            text = _redact_text(block.text)
            changed = changed or text != block.text
            content.append(types.TextContent(type="text", text=text, annotations=block.annotations, _meta=block.meta))
        else:
            content.append(block)
    if not changed:
        return result
    return result.model_copy(update={"content": content})


def _audit(log_path: Path | None, event: dict[str, Any]) -> None:
    if log_path is None:
        return
    log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    event = {"ts": time.time(), **event}
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, separators=(",", ":"), sort_keys=True) + "\n")
    os.chmod(log_path, 0o600)


def create_app(
    command: list[str] | None = None,
    *,
    public_base_url: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    oauth_db: str | None = None,
    audit_log: str | None = None,
):
    backend = StdioMCPBackend(command or ["mcp-combiner", "--fs-root", os.path.expanduser("~/dev")])
    audit_path = Path(audit_log).expanduser() if audit_log else None

    @asynccontextmanager
    async def lifespan(_: Server):
        try:
            yield {"backend": backend}
        finally:
            await backend.close()

    async def list_tools(_ctx: Any, _params: Any) -> types.ListToolsResult:
        raw_tools = await backend.list_tools()
        return types.ListToolsResult(tools=[types.Tool.model_validate(tool) for tool in raw_tools])

    async def call_tool(_ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        name = params.name
        arguments = params.arguments or {}
        started = time.monotonic()
        blocked = None
        if name.startswith("fs__"):
            blocked = _guard_filesystem(arguments)
        elif name == "cmd__run_process":
            blocked = _guard_command(arguments)
        if blocked:
            _audit(audit_path, {"client": "oauth", "tool": name, "outcome": "blocked", "reason": blocked})
            return types.CallToolResult(
                isError=True,
                content=[types.TextContent(type="text", text=f"SIN Mac Gateway policy: {blocked}")],
            )
        try:
            raw = await backend.call_tool(name, arguments)
            result = types.CallToolResult.model_validate(raw)
            if name == "cmd__run_process":
                result = _redact_call_result(result)
            _audit(
                audit_path,
                {
                    "client": "oauth" if public_base_url else "local",
                    "tool": name,
                    "outcome": "ok" if not result.is_error else "tool_error",
                    "duration_ms": int((time.monotonic() - started) * 1000),
                },
            )
            return result
        except Exception as exc:
            _audit(
                audit_path,
                {
                    "client": "oauth" if public_base_url else "local",
                    "tool": name,
                    "outcome": "gateway_error",
                    "error_type": type(exc).__name__,
                    "duration_ms": int((time.monotonic() - started) * 1000),
                },
            )
            raise

    server = Server(
        "SIN Mac Gateway",
        version="0.2.0",
        description="Authenticated provider-neutral MCP bridge to a trusted SIN Mac",
        instructions="Use the exposed filesystem and command tools only for the operator's requested Mac work.",
        lifespan=lifespan,
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )

    async def health(_: Request) -> Response:
        return PlainTextResponse("live")

    async def ready(_: Request) -> Response:
        try:
            tools = await backend.list_tools()
        except Exception as exc:
            return PlainTextResponse(f"not-ready:{type(exc).__name__}", status_code=503)
        return JSONResponse({"status": "ready", "tools": len(tools), "auth": bool(public_base_url)})

    custom_routes = [
        Route("/healthz", health, methods=["GET"]),
        Route("/readyz", ready, methods=["GET"]),
    ]

    auth_settings = None
    token_verifier = None
    auth_provider = None
    transport_security = None
    if public_base_url:
        if not client_id or not client_secret:
            raise ValueError("public OAuth mode requires client_id and client_secret")
        public_base_url = public_base_url.rstrip("/")
        resource_url = f"{public_base_url}/mcp"
        db_path = oauth_db or os.path.expanduser("~/.local/state/sin-mac-gateway/oauth.sqlite3")
        auth_provider = SQLiteOAuthProvider(db_path=db_path, client_id=client_id, client_secret=client_secret)
        token_verifier = ProviderTokenVerifier(auth_provider)
        auth_settings = AuthSettings(
            issuer_url=AnyHttpUrl(public_base_url),
            resource_server_url=AnyHttpUrl(resource_url),
            client_registration_options=ClientRegistrationOptions(
                enabled=False,
                valid_scopes=["mac"],
                default_scopes=["mac"],
            ),
            revocation_options=RevocationOptions(enabled=True),
            required_scopes=["mac"],
        )
        host = urlparse(public_base_url).netloc
        transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[host, f"{host}:443", "127.0.0.1", "127.0.0.1:*", "localhost", "localhost:*"],
            allowed_origins=["https://claude.ai", "https://claude.com"],
        )
    else:
        transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["127.0.0.1", "127.0.0.1:*", "localhost", "localhost:*"],
            allowed_origins=["http://127.0.0.1:*", "http://localhost:*"],
        )

    return server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        auth=auth_settings,
        token_verifier=token_verifier,
        auth_server_provider=auth_provider,
        custom_starlette_routes=custom_routes,
        transport_security=transport_security,
        host="127.0.0.1",
    )


def _default_roots() -> list[str]:
    candidates = [Path.home() / "dev", Path.home() / "orca"]
    roots = [str(path) for path in candidates if path.exists()]
    return roots or [str(Path.home())]


def main() -> None:
    parser = argparse.ArgumentParser(description="SIN Mac Gateway")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--fs-root", action="append", default=[])
    parser.add_argument("--combiner", default=os.environ.get("SIN_MAC_GATEWAY_COMBINER", "mcp-combiner"))
    parser.add_argument("--public-base-url", default=os.environ.get("SIN_MAC_GATEWAY_PUBLIC_BASE_URL"))
    parser.add_argument("--oauth-db", default=os.environ.get("SIN_MAC_GATEWAY_OAUTH_DB"))
    parser.add_argument("--audit-log", default=os.environ.get("SIN_MAC_GATEWAY_AUDIT_LOG"))
    args = parser.parse_args()

    roots = args.fs_root or _default_roots()
    command = [args.combiner]
    for root in roots:
        command.extend(["--fs-root", root])

    client_id = os.environ.get("SIN_MAC_GATEWAY_CLIENT_ID")
    client_secret = os.environ.get("SIN_MAC_GATEWAY_CLIENT_SECRET")
    application = create_app(
        command,
        public_base_url=args.public_base_url,
        client_id=client_id,
        client_secret=client_secret,
        oauth_db=args.oauth_db,
        audit_log=args.audit_log,
    )
    uvicorn.run(application, host=args.host, port=args.port, proxy_headers=True, forwarded_allow_ips="127.0.0.1")


if __name__ == "__main__":
    main()
