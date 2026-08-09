#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx

CALLBACK = "https://claude.ai/api/mcp/auth_callback"


def main() -> None:
    parser = argparse.ArgumentParser(description="End-to-end OAuth + MCP smoke test without printing secrets")
    parser.add_argument("--config", default="~/.config/sin-mac-gateway/config.json")
    args = parser.parse_args()
    config = json.loads(Path(args.config).expanduser().read_text(encoding="utf-8"))
    secret = Path(config["client_secret_file"]).expanduser().read_text(encoding="utf-8").strip()
    base = config["public_base_url"].rstrip("/")
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")

    with httpx.Client(timeout=30.0, follow_redirects=False) as client:
        auth = client.get(
            base + "/authorize",
            params={
                "response_type": "code",
                "client_id": config["client_id"],
                "redirect_uri": CALLBACK,
                "scope": "mac",
                "state": "smoke",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert auth.status_code == 302, auth.text
        code = parse_qs(urlparse(auth.headers["location"]).query)["code"][0]
        token = client.post(
            base + "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": config["client_id"],
                "client_secret": secret,
                "code": code,
                "redirect_uri": CALLBACK,
                "code_verifier": verifier,
            },
        )
        token.raise_for_status()
        token_data = token.json()
        access = token_data["access_token"]
        headers = {
            "Authorization": "Bearer " + access,
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        init = client.post(
            base + "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "public-smoke", "version": "1"},
                },
            },
        )
        init.raise_for_status()
        tools = client.post(base + "/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tools.raise_for_status()
        tool_names = [item["name"] for item in tools.json()["result"]["tools"]]
        call = client.post(
            base + "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "cmd__run_process",
                    "arguments": {
                        "argv": ["/bin/pwd"],
                        "cwd": str(Path.home() / "dev/SIN-Mac-Gateway"),
                        "timeout_ms": 30000,
                    },
                },
            },
        )
        call.raise_for_status()
        result = call.json()["result"]
        assert not result.get("isError", False), result
        revoke = client.post(
            base + "/revoke",
            data={"token": access, "client_id": config["client_id"], "client_secret": secret},
        )
        revoke.raise_for_status()
        rejected = client.post(base + "/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}})
        assert rejected.status_code == 401, rejected.text

    print(f"oauth=ok tools={len(tool_names)} cmd__run_process={'cmd__run_process' in tool_names} revoke=ok")


if __name__ == "__main__":
    main()
