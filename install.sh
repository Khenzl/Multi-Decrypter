#!/data/data/com.termux/files/usr/bin/bash

clear
echo -e "\033[1;36m"
echo "====================================="
echo "     Multi-Decrypter Installer       "
echo "====================================="
echo -e "\033[0m"

echo "[*] Memperbarui package..."
pkg update -y && pkg upgrade -y
pip install requests

echo "[*] Menginstal Python & Git..."
pkg install python

echo "[*] Menginstal pip dan modul Python..."
pip install -r requirements.txt

echo "[✓] Instalasi selesai!"
echo "[*] Jalankan dengan perintah: python multi_decrypter.py"
