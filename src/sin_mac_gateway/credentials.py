from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

from .secret_loader import read_secret_file_or_infisical


def _config() -> dict:
    path = Path(os.environ.get("SIN_MAC_GATEWAY_CONFIG", "~/.config/sin-mac-gateway/config.json")).expanduser()
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Show non-secret SIN Mac Gateway connector settings")
    parser.add_argument("--copy-secret", action="store_true", help="Copy OAuth client secret to the macOS clipboard without printing it")
    args = parser.parse_args()
    config = _config()
    print(f"name=SIN Mac Gateway")
    print(f"url={config['public_base_url']}/mcp")
    print(f"client_id={config['client_id']}")
    if args.copy_secret:
        secret = read_secret_file_or_infisical(config["client_secret_file"])
        subprocess.run(["/usr/bin/pbcopy"], input=secret.encode(), check=True)
        print("client_secret=copied-to-clipboard")
    else:
        print("client_secret=hidden (use --copy-secret)")


if __name__ == "__main__":
    main()
