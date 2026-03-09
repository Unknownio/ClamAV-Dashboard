#!/bin/bash

set -e

echo ""
echo "🛡  ShieldScan — Dependency Installer"
echo "────────────────────────────────────────"

# ── Detect distro ─────────────────────────────────────────────────────────────
if command -v apt &>/dev/null; then
    PKG_MANAGER="apt"
elif command -v pacman &>/dev/null; then
    PKG_MANAGER="pacman"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
else
    echo "❌  Could not detect package manager (apt/pacman/dnf)."
    echo "    Please install ClamAV and PyQt5 manually."
    exit 1
fi

echo "✔  Detected package manager: $PKG_MANAGER"

# ── Install ClamAV ────────────────────────────────────────────────────────────
if command -v clamscan &>/dev/null; then
    echo "✔  ClamAV already installed — skipping."
else
    echo "→  Installing ClamAV..."
    if [ "$PKG_MANAGER" = "apt" ]; then
        sudo apt update -qq
        sudo apt install -y clamav clamav-daemon
    elif [ "$PKG_MANAGER" = "pacman" ]; then
        sudo pacman -Sy --noconfirm clamav
    elif [ "$PKG_MANAGER" = "dnf" ]; then
        sudo dnf install -y clamav
    fi
    echo "✔  ClamAV installed."
fi

# ── Update virus definitions ──────────────────────────────────────────────────
echo "→  Updating ClamAV virus definitions (this may take a minute)..."
sudo freshclam || echo "⚠  freshclam failed — you can run it manually later: sudo freshclam"

# ── Install Python + pip ──────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "→  Installing Python 3..."
    if [ "$PKG_MANAGER" = "apt" ]; then
        sudo apt install -y python3 python3-pip
    elif [ "$PKG_MANAGER" = "pacman" ]; then
        sudo pacman -Sy --noconfirm python python-pip
    elif [ "$PKG_MANAGER" = "dnf" ]; then
        sudo dnf install -y python3 python3-pip
    fi
else
    echo "✔  Python 3 already installed — skipping."
fi

# ── Install PyQt5 ─────────────────────────────────────────────────────────────
echo "→  Installing PyQt5..."
pip3 install --break-system-packages -r requirements.txt 2>/dev/null \
    || pip3 install -r requirements.txt
echo "✔  PyQt5 installed."

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────"
echo "✅  All dependencies installed."
echo "    Run the app with:  python3 shieldscan.py"
echo ""
