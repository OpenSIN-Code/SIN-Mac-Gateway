# Security model

## Trust boundary

The public edge must authenticate before any MCP tool is callable. The gateway uses OAuth Authorization Code + S256 PKCE, short-lived access tokens, rotating refresh tokens, and revocation. OAuth state is stored outside Git with mode 0600.

The local HTTP listener binds to `127.0.0.1`. Public ingress is expected to be an outbound tunnel such as Cloudflare Tunnel; do not bind the service to `0.0.0.0` on an untrusted network.

## Shell authority

`cmd__run_process` is equivalent to user-level command execution. It is not an OS sandbox. The gateway blocks a small set of obvious Keychain/private-key/browser-secret access patterns and redacts high-confidence secret patterns from command output, but arbitrary code execution can bypass string-based guards. Treat any authenticated client with shell access as a trusted operator agent.

## Filesystem authority

`mcp-combiner --fs-root` remains the hard filesystem-server root. A defense-in-depth gateway guard rejects direct filesystem operations targeting `.ssh`, `.gnupg`, macOS Keychains, raw Chrome/Chromium profiles, and common credential filenames.

## Logging

The audit log records timestamp, tool name, outcome, duration and error class only. It does not record tool arguments, file contents, command output, OAuth tokens or client secrets.

## Secrets

Machine-specific OAuth client secrets, token databases, audit logs and Cloudflare credentials live under the user's private runtime/config directories and are gitignored by location rather than copied into this repository.
