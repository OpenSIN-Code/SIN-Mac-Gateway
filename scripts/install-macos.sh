#!/bin/sh
set -eu

REPO="${SIN_MAC_GATEWAY_REPO:-$HOME/dev/SIN-Mac-Gateway}"
VENV="${SIN_MAC_GATEWAY_VENV:-$HOME/.local/share/sin-mac-gateway/venv}"
BIN_DIR="$HOME/.local/bin"

[ -f "$REPO/pyproject.toml" ] || { echo "SIN Mac Gateway repo not found: $REPO" >&2; exit 1; }
python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install -q --upgrade pip
"$VENV/bin/python" -m pip install -q -e "$REPO"
mkdir -p "$BIN_DIR"
ln -sfn "$VENV/bin/sin-mac-gateway" "$BIN_DIR/sin-mac-gateway"
ln -sfn "$VENV/bin/sin-mac-gateway-bootstrap" "$BIN_DIR/sin-mac-gateway-bootstrap"
ln -sfn "$VENV/bin/sin-mac-gateway-credentials" "$BIN_DIR/sin-mac-gateway-credentials"
ln -sfn "$VENV/bin/sin-mac-gateway-service" "$BIN_DIR/sin-mac-gateway-service"
"$VENV/bin/sin-mac-gateway-bootstrap" "$@"
echo "installed: SIN Mac Gateway"
