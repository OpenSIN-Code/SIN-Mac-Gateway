# Operations

## Services

Gateway LaunchAgent: `com.sin.mac-gateway`.

A deployment may also install a separate tunnel LaunchAgent, for example `com.sin.mac-gateway.tunnel`. Both should use `RunAtLoad=true` and bare `KeepAlive=true`.

## Health

```bash
curl -fsS http://127.0.0.1:8765/healthz
curl -fsS http://127.0.0.1:8765/readyz
launchctl print "gui/$(id -u)/com.sin.mac-gateway"
```

`readyz` performs real backend discovery and reports the number of published tools.

## Connector credentials

```bash
sin-mac-gateway-credentials
sin-mac-gateway-credentials --copy-secret
```

The second command copies the OAuth secret to the macOS clipboard without printing it.

## Restart

```bash
launchctl kickstart -k "gui/$(id -u)/com.sin.mac-gateway"
```

## Rotate Claude client secret

Re-run bootstrap with `--rotate-client-secret`, then remove and re-add the Claude custom connector using the new secret. Existing OAuth tokens can be revoked or the private OAuth SQLite store can be removed while the service is stopped to invalidate all sessions.

## Logs and state

Default locations:

- `~/.config/sin-mac-gateway/config.json`
- `~/.config/sin-mac-gateway/oauth-client-secret` is a legacy source identifier; when the file is absent the runtime materializes it transiently from SIN-Infisical and immediately removes the temporary copy.
- `~/.local/state/sin-mac-gateway/oauth.sqlite3`
- `~/.local/state/sin-mac-gateway/audit.jsonl`
- `~/Library/Logs/SIN-Mac-Gateway/gateway.log`
- `~/Library/Logs/SIN-Mac-Gateway/gateway.err.log`

Never paste these secret-bearing files into issue reports.
