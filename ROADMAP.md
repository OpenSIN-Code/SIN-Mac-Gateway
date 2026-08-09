# Roadmap

## Completed

- Provider-neutral stdio backend bridge preserving `fs__*` / `cmd__*`.
- Official MCP Streamable HTTP transport.
- OAuth Authorization Code + S256 PKCE, refresh and revocation.
- Privacy-safe audit and defense-in-depth secret/path guards.
- launchd-managed macOS service and outbound Cloudflare Tunnel deployment.
- Public HTTPS end-to-end acceptance including a real `cmd__run_process` call and post-revocation 401.
- wow-my-zsh installer/doctor integration.

## Remaining interoperability work

- One-time Claude.ai UI enrollment after the operator signs in to Claude in an authorized browser session.
- Additional remote MCP client acceptance (Qwen/Gemini/other clients) as those surfaces expose compatible custom MCP configuration.
