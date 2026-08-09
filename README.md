# SIN Mac Gateway

Provider-neutral, authenticated Remote MCP gateway for a trusted macOS machine.

SIN Mac Gateway exposes the existing local `mcp-combiner` tool contract over the official MCP Python SDK's Streamable HTTP transport. The local backend remains the source of `fs__*` and `cmd__*`; this repository owns remote transport, OAuth, service lifecycle, audit/redaction safeguards, and deployment documentation.

## Architecture

```text
Claude.ai / remote MCP client
        |
        | HTTPS + OAuth 2.1 / PKCE
        v
Cloudflare Tunnel (outbound from Mac)
        |
        v
127.0.0.1:8765  SIN Mac Gateway
        |
        | stdio MCP
        v
mcp-combiner
   |         |
 fs__*     cmd__*
```

No router port is opened. The gateway itself binds to loopback; Cloudflare Tunnel is the public edge.

## Current capabilities

- Official `mcp==2.0.0` Streamable HTTP transport, including current protocol negotiation.
- OAuth Authorization Code flow with S256 PKCE.
- Persistent access/refresh tokens and revocation through a private SQLite store.
- Claude callback allowlist for `claude.ai` and `claude.com`.
- 401 Protected Resource Metadata discovery for unauthenticated MCP requests.
- Existing `mcp-combiner` compatibility: `fs__*` and `cmd__*` stay unchanged.
- Loopback `/healthz` and `/readyz` endpoints.
- launchd `RunAtLoad` + `KeepAlive` service.
- Privacy-safe audit log (tool/outcome/duration; arguments and outputs are not logged).
- High-confidence command-output secret redaction and a small defense-in-depth sensitive-path/Keychain guard.

`cmd__run_process` is still intentionally powerful user-level shell access. The guard is defense in depth, not an OS sandbox.

## Install on macOS

Prerequisite: the existing wow-my-zsh `mcp-combiner` runtime must be installed.

```bash
bash scripts/install-macos.sh \
  --public-base-url https://sin-mac-gateway.example.com \
  --fs-root "$HOME"
```

This creates private runtime/config state under `~/.config/sin-mac-gateway` and `~/.local/state/sin-mac-gateway`, installs a dedicated virtualenv under `~/.local/share/sin-mac-gateway`, and loads `com.sin.mac-gateway`.

Local verification:

```bash
curl -fsS http://127.0.0.1:8765/healthz
curl -fsS http://127.0.0.1:8765/readyz
```

## Claude.ai connector

Claude custom connectors connect from Anthropic infrastructure, so the MCP URL must be public HTTPS. Configure Claude with:

- Name: `SIN Mac Gateway`
- URL: `https://<hostname>/mcp`
- OAuth Client ID: shown by `sin-mac-gateway-credentials`
- OAuth Client Secret: run `sin-mac-gateway-credentials --copy-secret` and paste from the macOS clipboard

The secret command never prints the secret to stdout.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest -q
```

## Security

Runtime credentials, Cloudflare tunnel credentials, OAuth tokens, audit logs, and machine-specific config are never committed. See `docs/SECURITY.md` and `docs/OPERATIONS.md`.
