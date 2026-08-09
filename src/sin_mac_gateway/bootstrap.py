from __future__ import annotations

import argparse
import json
import os
import plistlib
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

LABEL = "com.sin.mac-gateway"
DEFAULT_PUBLIC_URL = "https://sin-mac-gateway.delqhi.com"


def _write_private(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(data, encoding="utf-8")
    path.chmod(0o600)


def _find_combiner() -> str:
    candidates = [Path.home() / "bin/mcp-combiner", Path.home() / ".local/bin/mcp-combiner"]
    for candidate in candidates:
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    found = shutil.which("mcp-combiner")
    if found:
        return found
    raise RuntimeError("mcp-combiner not found; install the wow-my-zsh gpt-web-mac connector first")


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap the persistent SIN Mac Gateway service")
    parser.add_argument("--public-base-url", default=DEFAULT_PUBLIC_URL)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--fs-root", action="append", default=[])
    parser.add_argument("--rotate-client-secret", action="store_true")
    parser.add_argument("--no-launchd", action="store_true")
    args = parser.parse_args()

    config_dir = Path.home() / ".config/sin-mac-gateway"
    state_dir = Path.home() / ".local/state/sin-mac-gateway"
    log_dir = Path.home() / "Library/Logs/SIN-Mac-Gateway"
    config_path = config_dir / "config.json"
    secret_path = config_dir / "oauth-client-secret"
    oauth_db = state_dir / "oauth.sqlite3"
    audit_log = state_dir / "audit.jsonl"

    existing: dict = {}
    if config_path.exists():
        existing = json.loads(config_path.read_text(encoding="utf-8"))
    client_id = existing.get("client_id") or f"claude-{secrets.token_hex(12)}"
    if args.rotate_client_secret or not secret_path.exists():
        _write_private(secret_path, secrets.token_urlsafe(48) + "\n")

    roots = args.fs_root or [str(Path.home())]
    config = {
        "version": 1,
        "public_base_url": args.public_base_url.rstrip("/"),
        "port": args.port,
        "client_id": client_id,
        "client_secret_file": str(secret_path),
        "oauth_db": str(oauth_db),
        "audit_log": str(audit_log),
        "combiner": _find_combiner(),
        "fs_roots": roots,
        "log_level": "info",
    }
    _write_private(config_path, json.dumps(config, indent=2, sort_keys=True) + "\n")
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    log_dir.mkdir(parents=True, exist_ok=True)

    print(f"configured: {config_path}")
    print(f"public MCP URL: {config['public_base_url']}/mcp")
    print(f"client id: {client_id}")
    print("client secret: stored privately; use sin-mac-gateway-credentials --copy-secret")

    if args.no_launchd:
        return

    plist_path = Path.home() / f"Library/LaunchAgents/{LABEL}.plist"
    plist = {
        "Label": LABEL,
        "ProgramArguments": [sys.executable, "-m", "sin_mac_gateway.service"],
        "EnvironmentVariables": {
            "SIN_MAC_GATEWAY_CONFIG": str(config_path),
            "PATH": f"{Path.home() / '.local/bin'}:{Path.home() / 'bin'}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        },
        "RunAtLoad": True,
        "KeepAlive": True,
        "ProcessType": "Background",
        "StandardOutPath": str(log_dir / "gateway.log"),
        "StandardErrorPath": str(log_dir / "gateway.err.log"),
    }
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    with plist_path.open("wb") as handle:
        plistlib.dump(plist, handle)
    plist_path.chmod(0o600)

    domain = f"gui/{os.getuid()}"
    subprocess.run(["/bin/launchctl", "bootout", domain, str(plist_path)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["/bin/launchctl", "bootstrap", domain, str(plist_path)], check=True)
    subprocess.run(["/bin/launchctl", "kickstart", "-k", f"{domain}/{LABEL}"], check=True)
    print(f"launchd: {LABEL} loaded")


if __name__ == "__main__":
    main()
