# 🔐 Multi-Decrypter - Termux Hash Cracker

**Multi-Decrypter** adalah tool berbasis Python di Termux untuk mendekripsi hash (MD5, SHA1, SHA256, dll) menggunakan wordlist lokal, API online, dan berbagai metode lainnya. Dibuat untuk ethical hacking dan edukasi keamanan siber.

---

## ✨ Fitur Utama

- 🔓 Dekripsi hash via wordlist lokal
- 🌐 Dekripsi via API online (lookup hash)
- 📁 Import hash massal dari file
- 🔢 Brute force angka
- 🔤 Brute force huruf + angka (soon)
- 📂 Simpan hasil ke folder `results/`
- 🎨 Tampilan terminal interaktif dengan banner ASCII

---

## 📦 Instalasi

```
pkg update && pkg upgrade

pkg install git

git clone https://github.com/Khenzl/Multi-Decrypter

cd Multi-Decrypter

chmod +x install.sh

bash install.sh

python multi_decrypter.py
