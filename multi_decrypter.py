import hashlib, os, time, requests, itertools, string, socket
import crypt
from bs4 import BeautifulSoup
from argon2 import PasswordHasher
from datetime import datetime

# Warna
R = '\033[91m'
G = '\033[92m'
C = '\033[96m'
Y = '\033[93m'
W = '\033[0m'
B = '\033[94m'
P = '\033[95m'

# Bersihkan layar
if os.name == 'nt':
    os.system('cls')  # Windows
else:
    os.system('clear')  # Linux / Termux / MacOS

# Banner
def banner():
    print(P + r"""


▖  ▖  ▜ ▗ ▘  ▄           ▗     
▛▖▞▌▌▌▐ ▜▘▌▄▖▌▌█▌▛▘▛▘▌▌▛▌▜▘█▌▛▘
▌▝ ▌▙▌▐▖▐▖▌  ▙▘▙▖▙▖▌ ▙▌▙▌▐▖▙▖▌ 
                     ▄▌▌""" + W)
    print(G + "[•] Tools By Khenzl | Multi Decrypter v1.0" + W)
    print(G + "[•] Dibuat pada Tanggal 26 Juli 2025" + W)
    print(G + "[•] Team Cyber of Sang Topi Hitam" + W)

# Cek koneksi internet
def cek_koneksi():
    try:
        socket.create_connection(("1.1.1.1", 80), timeout=5)
        return True
    except OSError:
        return False

# Tidak ada koneksi
if not cek_koneksi():
    print(R + "[!] Tidak ada koneksi internet!" + W)
    sys.exit()

# Simpan hasil
def simpan_hasil(hash_input, hasil):
    os.makedirs("results", exist_ok=True)
    with open("results/results.txt", "a") as f:
        f.write(f"[{datetime.now()}] Hash: {hash_input} => {hasil}\n")

# Hash Generator
def generate_hash(plaintext, algo):
    if algo == 'md5':
        return hashlib.md5(plaintext.encode()).hexdigest()
    elif algo == 'sha1':
        return hashlib.sha1(plaintext.encode()).hexdigest()
    elif algo == 'sha256':
        return hashlib.sha256(plaintext.encode()).hexdigest()
    elif algo == 'sha512':
        return hashlib.sha512(plaintext.encode()).hexdigest()
    elif algo == 'sha3_256':
        return hashlib.sha3_256(plaintext.encode()).hexdigest()
    elif algo == 'sha3_512':
        return hashlib.sha3_512(plaintext.encode()).hexdigest()
    elif algo == 'bcrypt':
        return bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt()).decode()
    elif algo == 'argon2':
        return PasswordHasher().hash(plaintext)
    return None

def hash_compare(hash_input, guess, algo):
    try:
        if algo in ['md5', 'sha1', 'sha256', 'sha512', 'sha3_256', 'sha3_512']:
            return generate_hash(guess, algo) == hash_input
        elif algo == 'bcrypt':
            return bcrypt.checkpw(guess.encode(), hash_input.encode())
        elif algo == 'argon2':
            return PasswordHasher().verify(hash_input, guess)
    except:
        return False
    return False

# Tambahan: Menu kembali/batalkan
def kembali_menu():
    input(Y + "\nTekan Enter untuk kembali ke menu utama..." + W)

# 1. Dekripsi Lokal
def dekripsi_lokal():
    try:
        os.system("clear")
        banner()
        algos = [
            'md5', 'sha1', 'sha256', 'sha512',
            'sha3_256', 'sha3_512', 'bcrypt', 'argon2'
        ]
        print(C + "\nPilih algoritma hash:" + W)
        for i, a in enumerate(algos, 1):
            print(f"[{i}] {a}")
        print(R + "[0] Batalkan" + W)

        pilih = input("Masukkan nomor algoritma: ")
        if pilih == '0':
            return
        pilih = int(pilih)

        if 1 <= pilih <= len(algos):
            algo = algos[pilih - 1]
        else:
            print(R + "[!] Pilihan tidak valid." + W)
            return

        hash_input = input("Masukkan hash: ").strip()
        ditemukan = False

        with open("wordlist.txt", "r", encoding="utf-8") as file:
            for kata in file:
                kata = kata.strip()
                if not kata:
                    continue
                if hash_compare(hash_input, kata, algo):
                    print(G + f"\n[\u2713] Hash ditemukan!" + W)
                    print(f"{C}Hash     : {W}{hash_input}")
                    print(f"{C}Password : {W}{kata}")
                    ditemukan = True

                    # Tanya apakah ingin menyimpan hasil
                    simpan = input("\nSimpan hasil ke file? (y/n): ").strip().lower()
                    if simpan == 'y':
                        folder = "Decrypt Lokal"
                        os.makedirs(folder, exist_ok=True)
                        waktu = datetime.now().strftime("%Y%m%d-%H%M%S")
                        nama_file = f"{folder}/hasil_{waktu}.txt"
                        with open(nama_file, "w", encoding="utf-8") as hasil:
                            hasil.write("=== Hasil Dekripsi Lokal ===\n")
                            hasil.write(f"Algoritma : {algo}\n")
                            hasil.write(f"Hash      : {hash_input}\n")
                            hasil.write(f"Password  : {kata}\n")
                        print(G + f"[✓] Hasil disimpan: {nama_file}" + W)
                    break

        if not ditemukan:
            print(R + "\n[X] Tidak ditemukan di wordlist." + W)

    except KeyboardInterrupt:
        print(R + "\n[!] Dibatalkan oleh pengguna." + W)
    finally:
        kembali_menu()
        os.system("clear")
        banner()

# 2. Password to Hash
def password_to_hash():
    try:
        os.system("clear")
        banner()
        while True:
            print(C + "\n=== Password to Hash Generator ===" + W)
            password = input(G + "[•] Masukkan Password yang ingin di Hash: " + W)
            if not password:
                print(Y + "[!] Password tidak boleh kosong.\n" + W)
                continue

            print(C + """
[1] MD5
[2] SHA1
[3] SHA256
[4] SHA512
[5] SHA3_256
[6] SHA3_512
""" + R + "[0] Batal / Kembali" + W)

            algo = input(G + "[•] Pilih algoritma hash: " + W)

            if algo == "0":
                print(Y + "[•] Dibatalkan.\n" + W)
                kembali_menu()
                os.system("clear")
                banner()
                break

            elif algo == "1":
                hasil = hashlib.md5(password.encode()).hexdigest()
                jenis = "MD5"
            elif algo == "2":
                hasil = hashlib.sha1(password.encode()).hexdigest()
                jenis = "SHA1"
            elif algo == "3":
                hasil = hashlib.sha256(password.encode()).hexdigest()
                jenis = "SHA256"
            elif algo == "4":
                hasil = hashlib.sha512(password.encode()).hexdigest()
                jenis = "SHA512"
            elif algo == "5":
                hasil = hashlib.sha3_256(password.encode()).hexdigest()
                jenis = "SHA3_256"
            elif algo == "6":
                hasil = hashlib.sha3_512(password.encode()).hexdigest()
                jenis = "SHA3_512"
            else:
                print(R + "[!] Pilihan tidak valid." + W)
                continue

            print(C + f"\n[✓] Hash {jenis}:\n{Y}{hasil}" + W)

            simpan = input(G + "[•] Simpan hasil ke file? (y/n): " + W)
            if simpan.lower() == 'y':
                os.makedirs("Password_Hash", exist_ok=True)
                with open("Password_Hash/password_hash.txt", "a") as f:
                    f.write(f"[{jenis}] {password} => {hasil}\n")
                print(G + "[✓] Hasil disimpan ke Password_Hash/password_hash.txt\n" + W)

            kembali_menu()
            os.system("clear")
            banner()
            break
    except KeyboardInterrupt:
        print(R + "\n[!] Dibatalkan oleh pengguna.\n" + W)
        kembali_menu()
        os.system("clear")
        banner()

# 3. API Lookup
def api_lookup():
    try:
        os.system("clear")
        banner()
        print(C + "\n=== Lookup Hash via API md5decrypt.net ===" + W)
        email = input(Y + "Masukkan email yang terdaftar di md5decrypt.net: " + W).strip()
        api_key = input(Y + "Masukkan API key: " + W).strip()

        print("\nPilih algoritma:")
        print("[1] MD5")
        print("[2] SHA1")
        print("[3] SHA256")
        print(R + "[0] Batalkan" + W)
        pilihan = input(C + "Masukkan pilihan (/1/2/3): " + W).strip()

        if pilihan == "0":
            return
        elif pilihan == "1":
            algo = "md5"
        elif pilihan == "2":
            algo = "sha1"
        elif pilihan == "3":
            algo = "sha256"
        else:
            print(R + "[X] Pilihan tidak valid." + W)
            return

        hash_input = input(Y + "Masukkan hash: " + W).strip()

        url = f"https://md5decrypt.net/Api/api.php?hash={hash_input}&hash_type={algo}&email={email}&code={api_key}"
        response = requests.get(url)
        if response.status_code == 200:
            result = response.text.strip()
            if result and "ERROR" not in result:
                print(G + f"[\u2713] Hash ditemukan!" + W)
                print(C + f"\nHasil:\nHash: {hash_input}\nPassword: {result}\n" + W)

                simpan = input(Y + "Ingin menyimpan hasil ini ke hash_api.txt? (y/n): " + W).strip().lower()
                if simpan == "y":
                    hasil = f"{hash_input} => {result}\n"
                    file_path = "hash_api.txt"
                    # Cek jika hash sudah ada
                    if os.path.exists(file_path):
                        with open(file_path, "r") as f:
                            if hasil in f.read():
                                print(Y + "[!] Hash sudah tersimpan sebelumnya." + W)
                                return
                    with open(file_path, "a") as f:
                        f.write(hasil)
                    print(G + "[\u2713] Hasil berhasil disimpan ke hash_api.txt" + W)
                else:
                    print(Y + "[!] Hasil tidak disimpan." + W)
            else:
                print(R + "[X] Hash tidak ditemukan di database." + W)
        else:
            print(R + f"[!!] Error status: {response.status_code}" + W)

    except KeyboardInterrupt:
        print(R + "\n[!] Dibatalkan oleh pengguna." + W)
    except Exception as e:
        print(R + f"[!!] Error koneksi: {e}" + W)
    finally:
        kembali_menu()
        os.system("clear")
        banner()

# 4. Brute Force Angka
def brute_force_angka():
    try:
        while True:
            os.system("clear")
            banner()
            print(C + "\n=== Brute Force Angka (0–99999) ===" + W)
            print(Y + "[1] MD5\n[2] SHA1\n[3] SHA224\n[4] SHA256\n[5] SHA384\n[6] SHA512\n[7] SHA3-256\n[8] SHA3-512\n[9] BLAKE2b" + W)
            print(R + "[0] Kembali" + W)
            algo_opt = input(C + "Pilih algoritma hash (0-9): " + W)

            if algo_opt == "0":
                print(Y + "[•] Kembali ke menu sebelumnya.\n" + W)
                return

            algo_map = {
                '1': 'md5',
                '2': 'sha1',
                '3': 'sha224',
                '4': 'sha256',
                '5': 'sha384',
                '6': 'sha512',
                '7': 'sha3_256',
                '8': 'sha3_512',
                '9': 'blake2b'
            }

            algo = algo_map.get(algo_opt)
            if not algo:
                print(R + "[X] Pilihan tidak valid." + W)
                continue

            hash_input = input("Masukkan hash: ").strip()

            found = False
            for i in range(100000):
                guess = str(i)
                h = getattr(hashlib, algo)(guess.encode()).hexdigest()
                if h == hash_input:
                    print(G + f"[\u2713] Ditemukan: {guess}" + W)
                    simpan_hasil(hash_input, guess)
                    found = True
                    break

            if not found:                                                                                                                                                                           print(R + "[X] Tidak ditemukan." + W)

            break
    except KeyboardInterrupt:
        print(R + "\n[!] Dibatalkan oleh pengguna." + W)
    finally:
        kembali_menu()
        os.system("clear")
        banner()

# 5.Brute Force Huruf + Angka
def brute_force_alnum():
    hash_input = ""
    algo = ""
    total_tried = 0                                                                                                                                   
    start_time = time.time()

    try:
        os.system("clear")
        banner()
        print(C + "\n=== Brute Force Huruf + Angka ===" + W)
        print(Y + "[1] MD5\n[2] SHA1\n[3] SHA256\n[4] SHA512\n[5] SHA3_224\n[6] SHA3_256\n[7] SHA3_384\n[8] SHA3_512\n[9] SHAKE_128" + W)
        print(R + "[0] Kembali" + W)
        algo_opt = input(C + "Pilih algoritma hash (0-9): " + W)

        if algo_opt == '0':
            print(Y + "[!] Kembali ke menu utama..." + W)
            kembali_menu()
            os.system("clear")
            banner()
            return

        algo_map = {
            '1': 'md5',
            '2': 'sha1',
            '3': 'sha256',
            '4': 'sha512',
            '5': 'sha3_224',
            '6': 'sha3_256',
            '7': 'sha3_384',
            '8': 'sha3_512',
            '9': 'shake_128'
        }

        algo = algo_map.get(algo_opt)
        if not algo:
            print(R + "[X] Pilihan tidak valid." + W)
            kembali_menu()
            os.system("clear")
            banner()
            return

        hash_input = input(C + f"Masukkan hash ({algo.upper()}): " + W)

        print(Y + "\nPilih kombinasi karakter:" + W)
        print(Y + "[1] Huruf kecil + angka" + W)
        print(Y + "[2] Huruf besar + kecil + angka" + W)
        print(Y + "[3] Huruf + angka + simbol" + W)
        charset_opt = input(C + "Pilihan karakter (1/2/3): " + W)

        if charset_opt == '1':
            chars = string.ascii_lowercase + string.digits
        elif charset_opt == '2':
            chars = string.ascii_letters + string.digits
        elif charset_opt == '3':
            chars = string.ascii_letters + string.digits + string.punctuation
        else:
            print(R + "[X] Pilihan karakter tidak valid." + W)
            kembali_menu()
            os.system("clear")
            banner()
            return

        max_len = input(C + "Panjang maksimum kombinasi (1–6): " + W)
        if not max_len.isdigit() or int(max_len) < 1 or int(max_len) > 6:
            print(R + "[X] Panjang tidak valid (1–6)." + W)
            kembali_menu()
            os.system("clear")
            banner()
            return
        max_len = int(max_len)

        limit = input(C + "Maksimal percobaan (Enter untuk tak terbatas): " + W)
        limit = int(limit) if limit.isdigit() else None

        print(Y + "[*] Memulai brute force..." + W)
        start_time = time.time()

        for panjang in range(1, max_len + 1):
            for kombinasi in itertools.product(chars, repeat=panjang):
                kata = ''.join(kombinasi)
                total_tried += 1

                if limit and total_tried > limit:
                    print(R + f"[!] Batas percobaan ({limit}) tercapai." + W)
                    tulis_log(hash_input, algo, False, total_tried, start_time)
                    kembali_menu()
                    os.system("clear")
                    banner()
                    return

                try:
                    if algo == "shake_128":
                        h = hashlib.shake_128()
                        h.update(kata.encode())
                        hashed = h.hexdigest(32)
                    else:
                        h = hashlib.new(algo)
                        h.update(kata.encode())
                        hashed = h.hexdigest()
                except Exception as e:
                    print(R + f"[!] Error saat hashing: {e}" + W)
                    continue

                if hashed == hash_input:
                    end_time = time.time()
                    durasi = end_time - start_time
                    print(G + f"[\u2713] Ditemukan: {kata} (dalam {durasi:.2f} detik)" + W)
                    simpan_hasil(hash_input, kata)
                    tulis_log(hash_input, algo, True, total_tried, start_time, kata)
                    kembali_menu()
                    os.system("clear")
                    banner()
                    return

        print(R + "[X] Tidak ditemukan setelah mencoba", total_tried, "kombinasi." + W)
        tulis_log(hash_input, algo, False, total_tried, start_time)
        kembali_menu()
        os.system("clear")
        banner()

    except KeyboardInterrupt:
        print(R + "\n[!] Dibatalkan oleh pengguna." + W)
        try:
            tulis_log(hash_input, algo, False, total_tried, start_time, dibatalkan=True)
        except:
            pass  # Jaga-jaga kalau `algo` belum terisi
        kembali_menu()
        os.system("clear")
        banner()

# 6. Import Hash Massal (versi lengkap dengan fitur tambahan)
def import_massal():
    try:
        os.system("clear")
        banner()
        print(C + "\n=== Import Hash Massal dari File ===" + W)
        filepath = input(Y + "Masukkan path file hash (cth: hashes.txt): " + W)
        if not os.path.isfile(filepath):
            print(R + "[!] File tidak ditemukan!" + W)
            return

        wordlist_path = input(Y + "Masukkan path file wordlist (Enter untuk default: wordlist.txt): " + W)
        if not wordlist_path:
            wordlist_path = "wordlist.txt"

        if not os.path.isfile(wordlist_path):
            print(R + "[!] Wordlist tidak ditemukan!" + W)
            return

        print(C + "\nPilih algoritma hash:" + W)
        print(Y + "[1] MD5\n[2] SHA1\n[3] SHA256\n[4] SHA512\n[5] SHA3_256\n[6] SHA3_512" + W)
        print(R + "[0] Batalkan" + W)
        algo_opt = input(C + "Pilih algoritma (1-6): " + W)

        algo_map = {
            '1': 'md5',
            '2': 'sha1',
            '3': 'sha256',
            '4': 'sha512',
            '5': 'sha3_256',
            '6': 'sha3_512'
        }

        if algo_opt == '0':
            return

        algo = algo_map.get(algo_opt)
        if not algo:
            print(R + "[X] Pilihan tidak valid." + W)
            return

        # Baca file
        with open(filepath, "r", encoding="utf-8") as f:
            hashes = list(set(line.strip() for line in f if line.strip()))

        with open(wordlist_path, "r", encoding="utf-8") as w:
            wordlist = [line.strip() for line in w if line.strip()]

        print(Y + f"\n[*] Total hash: {len(hashes)}" + W)
        print(Y + f"[*] Total kata di wordlist: {len(wordlist)}" + W)
        print(Y + "[*] Memulai proses dekripsi massal...\n" + W)

        # Buat folder dan nama file output
        os.makedirs("Hash_Masal", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"Hash_Masal/hash_masal_{timestamp}.txt"

        found = 0
        start = time.time()

        for h in hashes:
            print(C + f"[•] Dekripsi: {h}" + W)
            ketemu = False
            for word in wordlist:
                if hash_compare(h, word, algo):
                    print(G + f"[✓] {h} => {word}" + W)
                    with open(output_file, "a", encoding="utf-8") as out:
                        out.write(f"{h} => {word}\n")
                    simpan_hasil(h, word)
                    found += 1
                    ketemu = True
                    break
            if not ketemu:
                print(R + f"[X] Tidak ditemukan untuk: {h}" + W)

        durasi = time.time() - start
        print(C + f"\n=== Ringkasan Dekripsi ===" + W)
        print(G + f"✓ Total berhasil didekripsi: {found}" + W)
        print(Y + f"• Total hash yang diproses : {len(hashes)}" + W)
        print(Y + f"• Durasi proses            : {durasi:.2f} detik" + W)

        if found > 0:
            print(G + f"\n✓ Hasil disimpan ke: {output_file}" + W)
        else:
            print(R + "[!] Tidak ada hasil yang disimpan karena tidak ditemukan." + W)

    except KeyboardInterrupt:
        print(R + "\n[!] Dibatalkan oleh pengguna." + W)
    except Exception as e:
        print(R + f"[!!] Terjadi kesalahan: {e}" + W)
    finally:
        kembali_menu()
        os.system("clear")
        banner()

# Menu Utama
def menu():
    banner()
    while True:
        try:
            print(Y + """
========== Menu Multi-Decrypter ==========
""" + C + """
[1] Decrypter Lokal (Wordlist)
[2] Password to Hash (Generator)
[3] API Lookup (Online)
[4] Brute Force Angka (1–99999)
[5] Brute Force Huruf+Angka
[6] Import Hash Massal
""" + R + "[0] Keluar" + W)
            pilihan = input("Pilih menu: ")
            if pilihan == '1': dekripsi_lokal()
            elif pilihan == "2": password_to_hash()
            elif pilihan == '3': api_lookup()
            elif pilihan == '4': brute_force_angka()
            elif pilihan == '5': brute_force_alnum()
            elif pilihan == '6': import_massal()
            elif pilihan == '0':
                print(G + "Keluar... Happy Nice Day!" + W)
                break
            else:
                print(R + "Pilihan tidak valid" + W)
        except KeyboardInterrupt:
            print(R + "\n[!] Dibatalkan oleh pengguna." + W)
            break

menu()
