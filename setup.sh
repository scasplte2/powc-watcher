#!/usr/bin/env bash
#
# PoWC-Watcher Setup Script
# Installs dependencies and initializes configuration
#

set -euo pipefail

echo "🚀 PoWC-Watcher Setup"
echo ""

# Detect OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$ID
else
    echo "❌ Cannot detect OS"
    exit 1
fi

# Install system dependencies
echo "📦 Installing system dependencies..."
if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]] || [[ "$OS" == "pop" ]] || [[ "$OS" =~ "debian" ]]; then
    echo "Detected Debian-based system: $OS"
    sudo apt-get update
    sudo apt-get install -y inotify-tools jq curl python3 python3-pip python3-venv attr
elif [[ "$OS" == "fedora" ]] || [[ "$OS" == "rhel" ]] || [[ "$OS" == "centos" ]]; then
    echo "Detected Red Hat-based system: $OS"
    sudo dnf install -y inotify-tools jq curl python3 python3-pip
elif [[ "$OS" == "arch" ]] || [[ "$OS" == "manjaro" ]]; then
    echo "Detected Arch-based system: $OS"
    sudo pacman -S --noconfirm inotify-tools jq curl python python-pip
else
    echo "⚠️  Detected: $OS"
    echo "Attempting Debian-style package installation..."
    if sudo apt-get update &>/dev/null; then
        sudo apt-get install -y inotify-tools jq curl python3 python3-pip python3-venv attr
    else
        echo "❌ Could not determine package manager"
        echo "Please manually install: inotify-tools jq curl python3 python3-pip python3-venv attr"
        exit 1
    fi
fi

# Install Python dependencies
echo "🐍 Setting up Python environment..."
echo ""
echo "Choose Python installation method:"
echo "  1) Virtual environment (venv) - Recommended, isolated"
echo "  2) Global installation - System-wide"
echo ""
read -p "Enter choice [1-2] (default: 1): " choice
choice=${choice:-1}

if [[ "$choice" == "1" ]]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    echo "✅ Virtual environment created at ./venv"
    echo ""
    echo "⚠️  To use the watcher, the script will automatically use the venv."
else
    echo "📦 Installing globally..."
    pip install ecdsa rfc8785
    echo "✅ Installed globally"
fi

# Create config from example
if [[ ! -f config/powc.conf ]]; then
    echo "⚙️  Creating config file..."
    cp config/powc.conf.example config/powc.conf
    echo "✅ Created config/powc.conf"
    echo ""
    echo "⚠️  IMPORTANT: Edit config/powc.conf and add your credentials:"
    echo "   - ORG_ID"
    echo "   - TENANT_ID"
    echo "   - API_KEY"
    echo ""
else
    echo "⚠️  config/powc.conf already exists (skipping)"
fi

# Create directories
mkdir -p watched_files logs output config

# Make scripts executable
chmod +x powc-watcher.sh src/powc_signer.py

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Edit config/powc.conf with your Digital Evidence credentials"
echo "  2. Run: ./powc-watcher.sh"
echo ""
