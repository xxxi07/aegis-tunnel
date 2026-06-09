#!/bin/bash
# AEGIS-Tunnel deployment script
# Usage: sudo ./install.sh [server|client]
set -euo pipefail

ROLE="${1:-server}"
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"
CONF_DIR="/etc/aegis"

echo "=== AEGIS-Tunnel Installer ==="
echo "Role: $ROLE"
echo "Prefix: $INSTALL_PREFIX"
echo ""

# ── Build ──
echo "[1/6] Building..."
cd "$(dirname "$0")/.."
make -j$(nproc) 2>/dev/null || {
    cmake -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build -j$(nproc)
}
echo "  Build complete"

# ── Install binary ──
echo "[2/6] Installing binary..."
install -D -m 755 build/aegis-tunnel "$INSTALL_PREFIX/bin/aegis-tunnel"
echo "  → $INSTALL_PREFIX/bin/aegis-tunnel"

# ── Install shared library ──
echo "[3/6] Installing library..."
if [ -f build/libaegis-tunnel-lib.so ]; then
    install -D -m 755 build/libaegis-tunnel-lib.so \
        "$INSTALL_PREFIX/lib/libaegis-tunnel.so.0.1.0"
    ldconfig 2>/dev/null || true
    echo "  → $INSTALL_PREFIX/lib/libaegis-tunnel.so"
else
    echo "  (shared library not built — CMake required)"
fi

# ── Create config directory ──
echo "[4/6] Setting up config..."
mkdir -p "$CONF_DIR"
chmod 750 "$CONF_DIR"

# Copy example config
cp deploy/${ROLE}.conf.example "$CONF_DIR/${ROLE}.conf.example"
echo "  → $CONF_DIR/${ROLE}.conf.example"

# ── Generate PSK if missing ──
if [ ! -f "$CONF_DIR/psk.key" ]; then
    echo "[5/6] Generating PSK..."
    dd if=/dev/urandom bs=16 count=1 of="$CONF_DIR/psk.key" 2>/dev/null
    chmod 400 "$CONF_DIR/psk.key"
    echo "  → $CONF_DIR/psk.key (chmod 400)"
    echo "  ⚠️  Copy this file to the peer host!"
else
    echo "[5/6] PSK already exists at $CONF_DIR/psk.key"
fi

# ── Create user ──
echo "[6/6] Creating service user..."
if ! id aegis-tunnel &>/dev/null; then
    useradd -r -s /sbin/nologin -d /nonexistent aegis-tunnel
    echo "  → user 'aegis-tunnel' created"
else
    echo "  → user 'aegis-tunnel' already exists"
fi

# ── Install systemd service ──
echo ""
echo "To install the systemd service:"
echo "  sudo cp deploy/aegis-tunnel@.service /etc/systemd/system/"
echo "  sudo cp deploy/${ROLE}.conf.example /etc/aegis/${ROLE}.conf"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable --now aegis-tunnel@${ROLE}"
echo ""
echo "Done! ✓"
