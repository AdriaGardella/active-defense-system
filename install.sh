#!/bin/bash
# Active Defense System - Automated Installation Script

set -e  # Salir si hay errores

echo "========================================"
echo " Active Defense System - Installer"
echo "========================================"

# Verificar que se ejecuta como root
if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] This script must be run as root (sudo)" 
   exit 1
fi

echo "[1/6] Updating system packages..."
apt update -y && apt upgrade -y

echo "[2/6] Installing Suricata..."
add-apt-repository ppa:oisf/suricata-stable -y
apt update
apt install -y suricata jq

echo "[3/6] Installing Python and SQLite..."
apt install -y python3 python3-pip sqlite3

echo "[4/6] Copying custom Suricata rules..."
cp config/local.rules /etc/suricata/rules/local.rules

echo "[5/6] Configuring sudo permissions for iptables..."
echo "$SUDO_USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables" > /etc/sudoers.d/active-defense

echo "[6/6] Starting Suricata service..."
systemctl enable suricata
systemctl restart suricata

echo ""
echo "✓ Installation completed successfully!"
echo ""
echo "Next steps:"
echo "1. Edit /etc/suricata/suricata.yaml and set your network interface"
echo "2. Run: python3 active_defense.py"
echo ""