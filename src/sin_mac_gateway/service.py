from __future__ import annotations

import json
import os
from pathlib import Path

import uvicorn

from .app import create_app
from .secret_loader import read_secret_file_or_infisical


def _default_config_path() -> Path:
    return Path(os.environ.get("SIN_MAC_GATEWAY_CONFIG", "~/.config/sin-mac-gateway/config.json")).expanduser()


def load_config(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    required = {"client_id", "client_secret_file", "public_base_url", "port", "fs_roots", "combiner"}
    missing = required - set(data)
    if missing:
        raise RuntimeError(f"missing config keys: {', '.join(sorted(missing))}")
    return data


def main() -> None:
    config_path = _default_config_path()
    config = load_config(config_path)
    client_secret = read_secret_file_or_infisical(config["client_secret_file"])
    if len(client_secret) < 32:
        raise RuntimeError("OAuth client secret is missing or too short")

    command = [str(config["combiner"])]
    for root in config["fs_roots"]:
        command.extend(["--fs-root", str(Path(root).expanduser())])

    app = create_app(
        command,
        public_base_url=config["public_base_url"],
        client_id=config["client_id"],
        client_secret=client_secret,
        oauth_db=config.get("oauth_db"),
        audit_log=config.get("audit_log"),
    )
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=int(config["port"]),
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
        log_level=config.get("log_level", "info"),
    )


if __name__ == "__main__":
    main()
