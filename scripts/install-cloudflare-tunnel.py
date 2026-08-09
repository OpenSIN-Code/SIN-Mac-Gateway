#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import plistlib
import shutil
import subprocess
from pathlib import Path


def run(argv: list[str], *, capture: bool = False) -> str:
    result = subprocess.run(argv, check=True, text=True, capture_output=capture)
    return result.stdout if capture else ""


def main() -> None:
    parser = argparse.ArgumentParser(description="Install an outbound Cloudflare Tunnel for SIN Mac Gateway")
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--tunnel-name", default="sin-mac-gateway")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    cloudflared = shutil.which("cloudflared")
    if not cloudflared:
        raise SystemExit("cloudflared not found")

    tunnels = json.loads(run([cloudflared, "tunnel", "list", "--output", "json"], capture=True))
    tunnel = next((item for item in tunnels if item.get("name") == args.tunnel_name), None)
    if tunnel is None:
        created = json.loads(run([cloudflared, "tunnel", "create", "--output", "json", args.tunnel_name], capture=True))
        tunnel_id = created["id"]
    else:
        tunnel_id = tunnel["id"]

    credentials = Path.home() / f".cloudflared/{tunnel_id}.json"
    if not credentials.exists():
        raise SystemExit(f"tunnel credentials missing: {credentials}")

    run([cloudflared, "tunnel", "route", "dns", "--overwrite-dns", args.tunnel_name, args.hostname])

    config_dir = Path.home() / ".config/sin-mac-gateway"
    config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    config = config_dir / "cloudflared.yml"
    config.write_text(
        f"tunnel: {tunnel_id}\n"
        f"credentials-file: {credentials}\n"
        "ingress:\n"
        f"  - hostname: {args.hostname}\n"
        f"    service: http://127.0.0.1:{args.port}\n"
        "  - service: http_status:404\n",
        encoding="utf-8",
    )
    config.chmod(0o600)

    log_dir = Path.home() / "Library/Logs/SIN-Mac-Gateway"
    log_dir.mkdir(parents=True, exist_ok=True)
    label = "com.sin.mac-gateway.tunnel"
    plist_path = Path.home() / f"Library/LaunchAgents/{label}.plist"
    plist = {
        "Label": label,
        "ProgramArguments": [cloudflared, "tunnel", "--config", str(config), "run", args.tunnel_name],
        "RunAtLoad": True,
        "KeepAlive": True,
        "ProcessType": "Background",
        "StandardOutPath": str(log_dir / "tunnel.log"),
        "StandardErrorPath": str(log_dir / "tunnel.err.log"),
    }
    with plist_path.open("wb") as handle:
        plistlib.dump(plist, handle)
    plist_path.chmod(0o600)

    domain = f"gui/{os.getuid()}"
    subprocess.run(["/bin/launchctl", "bootout", domain, str(plist_path)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run(["/bin/launchctl", "bootstrap", domain, str(plist_path)])
    run(["/bin/launchctl", "kickstart", "-k", f"{domain}/{label}"])
    print(f"tunnel={args.tunnel_name}")
    print(f"hostname={args.hostname}")
    print(f"url=https://{args.hostname}/mcp")


if __name__ == "__main__":
    main()
