#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

echo "=== CyberGuard Professional Security Toolkit — Setup ==="
echo ""

# Python check
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 not found. Install with: sudo apt install python3 python3-venv"
    exit 1
fi

PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "[OK] Python $PY_VERSION"

# venv check / create
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    echo "[OK] venv created: $VENV_DIR"
else
    echo "[OK] venv exists: $VENV_DIR"
fi

# Activate and install
echo "[*] Installing dependencies..."
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install -r "$SCRIPT_DIR/requirements.txt" -q
echo "[OK] Dependencies installed"

# Test dependencies
if [ -f "$SCRIPT_DIR/requirements-test.txt" ]; then
    echo "[*] Installing test dependencies..."
    "$VENV_DIR/bin/pip" install -r "$SCRIPT_DIR/requirements-test.txt" -q
    echo "[OK] Test dependencies installed"
fi

# Verify imports
echo "[*] Verifying imports..."
"$VENV_DIR/bin/python" -c "
import rich, questionary, requests, dns, psutil, cryptography
print('[OK] All imports successful')
"

# Create launcher script
cat > "$SCRIPT_DIR/cyberguard" <<'LAUNCHER'
#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/venv/bin/python" "$SCRIPT_DIR/cyberguard_toolkit.py" "$@"
LAUNCHER
chmod +x "$SCRIPT_DIR/cyberguard"

echo ""
echo "=== Setup complete ==="
echo ""
echo "Run toolkit:  ./cyberguard"
echo "Run tests:    venv/bin/python -m pytest tests/ -v"
