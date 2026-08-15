from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path


def read_secret_file_or_infisical(source: str) -> str:
    path = Path(source).expanduser()
    if path.is_file():
        return path.read_text(encoding="utf-8").strip()
    cli = Path(os.environ.get("SIN_INFISICAL_BIN", "~/.local/bin/sin-infisical")).expanduser()
    if not cli.is_file():
        raise RuntimeError(f"secret source missing and sin-infisical unavailable: {path}")
    fd, tmp = tempfile.mkstemp(prefix="sin-mac-gateway-secret-")
    os.close(fd)
    tmp_path = Path(tmp)
    tmp_path.chmod(0o600)
    try:
        proc = subprocess.run(
            [str(cli), "agent", "materialize", "--source", str(path), "--dest", str(tmp_path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, check=False, timeout=30,
        )
        if proc.returncode != 0:
            raise RuntimeError("failed to materialize gateway secret from Infisical")
        return tmp_path.read_text(encoding="utf-8").strip()
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
