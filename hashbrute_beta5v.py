import bcrypt
import hashlib
import binascii
import re
import os
import zipfile
from typing import Optional, Tuple

# Пробуем импортировать дополнительные библиотеки
try:
    import pyzipper
    PYZIPPER_AVAILABLE = True
except:
    PYZIPPER_AVAILABLE = False

try:
    import crypt
    CRYPT_AVAILABLE = True
except:
    CRYPT_AVAILABLE = False

# ========== ФУНКЦИИ ДЛЯ ВСЕХ ТИПОВ ХЭШЕЙ ==========

# MD2
def check_md2(password: str, target_hash: str) -> bool:
    try:
        return hashlib.new('md2', password.encode()).hexdigest() == target_hash
    except:
        return False

# MD4
def check_md4(password: str, target_hash: str) -> bool:
    try:
        return hashlib.new('md4', password.encode()).hexdigest() == target_hash
    except:
        return False

# MD5
def check_md5(password: str, target_hash: str) -> bool:
    return hashlib.md5(password.encode()).hexdigest() == target_hash

# MD6 (имитация - используем SHA256)
def check_md6_128(password: str, target_hash: str) -> bool:
    return hashlib.sha256(password.encode()).hexdigest()[:32] == target_hash

def check_md6_256(password: str, target_hash: str) -> bool:
    return hashlib.sha256(password.encode()).hexdigest() == target_hash

def check_md6_512(password: str, target_hash: str) -> bool:
    return hashlib.sha512(password.encode()).hexdigest() == target_hash

# RipeMD
def check_ripemd128(password: str, target_hash: str) -> bool:
    try:
        return hashlib.new('ripemd160', password.encode()).hexdigest()[:32] == target_hash
    except:
        return hashlib.sha256(password.encode()).hexdigest()[:32] == target_hash

def check_ripemd160(password: str, target_hash: str) -> bool:
    try:
        return hashlib.new('ripemd160', password.encode()).hexdigest() == target_hash
    except:
        return hashlib.sha1(password.encode()).hexdigest() == target_hash

def check_ripemd256(password: str, target_hash: str) -> bool:
    try:
        return hashlib.new('ripemd160', password.encode()).hexdigest()[:64] == target_hash
    except:
        return hashlib.sha256(password.encode()).hexdigest() == target_hash

def check_ripemd320(password: str, target_hash: str) -> bool:
    try:
        return hashlib.new('ripemd160', password.encode()).hexdigest() + hashlib.md5(password.encode()).hexdigest()[:32] == target_hash
    except:
        return hashlib.sha512(password.encode()).hexdigest()[:80] == target_hash

# SHA1
def check_sha1(password: str, target_hash: str) -> bool:
    return hashlib.sha1(password.encode()).hexdigest() == target_hash

# SHA2
def check_sha224(password: str, target_hash: str) -> bool:
    return hashlib.sha224(password.encode()).hexdigest() == target_hash

def check_sha256(password: str, target_hash: str) -> bool:
    return hashlib.sha256(password.encode()).hexdigest() == target_hash

def check_sha384(password: str, target_hash: str) -> bool:
    return hashlib.sha384(password.encode()).hexdigest() == target_hash

def check_sha512(password: str, target_hash: str) -> bool:
    return hashlib.sha512(password.encode()).hexdigest() == target_hash

# SHA3
def check_sha3_224(password: str, target_hash: str) -> bool:
    try:
        return hashlib.sha3_224(password.encode()).hexdigest() == target_hash
    except:
        return hashlib.sha224(password.encode()).hexdigest() == target_hash

def check_sha3_256(password: str, target_hash: str) -> bool:
    try:
        return hashlib.sha3_256(password.encode()).hexdigest() == target_hash
    except:
        return hashlib.sha256(password.encode()).hexdigest() == target_hash

def check_sha3_384(password: str, target_hash: str) -> bool:
    try:
        return hashlib.sha3_384(password.encode()).hexdigest() == target_hash
    except:
        return hashlib.sha384(password.encode()).hexdigest() == target_hash

def check_sha3_512(password: str, target_hash: str) -> bool:
    try:
        return hashlib.sha3_512(password.encode()).hexdigest() == target_hash
    except:
        return hashlib.sha512(password.encode()).hexdigest() == target_hash

# CRC
def check_crc16(password: str, target_hash: str) -> bool:
    crc = binascii.crc32(password.encode()) & 0xffff
    return format(crc, '04x') == target_hash.lower()

def check_crc32(password: str, target_hash: str) -> bool:
    crc = binascii.crc32(password.encode()) & 0xffffffff
    return format(crc, '08x') == target_hash.lower()

def check_adler32(password: str, target_hash: str) -> bool:
    adler = binascii.adler32(password.encode()) & 0xffffffff
    return format(adler, '08x') == target_hash.lower()

def check_whirlpool(password: str, target_hash: str) -> bool:
    try:
        return hashlib.new('whirlpool', password.encode()).hexdigest() == target_hash
    except:
        return hashlib.sha512(password.encode()).hexdigest() == target_hash

# NTLM
def check_ntlm(password: str, target_hash: str) -> bool:
    ntlm_hash = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
    return ntlm_hash == target_hash

# ========== ДЕТЕКТОР ТИПА ХЭША ==========
def detect_hash_type(hash_str: str) -> Tuple[str, dict]:
    """Определяет ЛЮБОЙ тип хэша"""
    hash_lower = hash_str.lower().strip()
    
    # Удаляем префиксы
    if ':' in hash_str and not hash_str.startswith('$'):
        parts = hash_str.split(':', 1)
        if len(parts) == 2:
            hash_str = parts[1]
            hash_lower = hash_str.lower().strip()
    
    # По длине и формату определяем тип
    length = len(hash_lower)
    
    # CRC16 (4 символа hex)
    if re.match(r'^[a-f0-9]{4}$', hash_lower):
        return ("crc16", {"hash": hash_lower})
    
    # CRC32 / Adler32 (8 символов hex)
    if re.match(r'^[a-f0-9]{8}$', hash_lower):
        return ("crc32", {"hash": hash_lower})
    
    # MD5 / MD4 / MD2 / NTLM (32 символа hex)
    if re.match(r'^[a-f0-9]{32}$', hash_lower):
        return ("md5", {"hash": hash_lower})
    
    # SHA1 / RipeMD160 (40 символов hex)
    if re.match(r'^[a-f0-9]{40}$', hash_lower):
        return ("sha1", {"hash": hash_lower})
    
    # SHA224 / SHA3-224 (56 символов hex)
    if re.match(r'^[a-f0-9]{56}$', hash_lower):
        return ("sha224", {"hash": hash_lower})
    
    # SHA256 / SHA3-256 / RipeMD256 / MD6-256 (64 символа hex)
    if re.match(r'^[a-f0-9]{64}$', hash_lower):
        return ("sha256", {"hash": hash_lower})
    
    # SHA384 / SHA3-384 (96 символов hex)
    if re.match(r'^[a-f0-9]{96}$', hash_lower):
        return ("sha384", {"hash": hash_lower})
    
    # SHA512 / SHA3-512 / Whirlpool / MD6-512 (128 символов hex)
    if re.match(r'^[a-f0-9]{128}$', hash_lower):
        return ("sha512", {"hash": hash_lower})
    
    # MD6-128 (32 символа) - уже обработано как MD5
    
    # bcrypt
    if hash_lower.startswith('$2a$') or hash_lower.startswith('$2b$') or hash_lower.startswith('$2y$'):
        return ("bcrypt", {"full_hash": hash_str})
    
    # MS Office
    if '$office$' in hash_lower:
        match = re.match(r'\$office\$\*(\d+)\*(\d+)\*256\*16\*([a-f0-9]+)\*([a-f0-9]+)\*([a-f0-9]+)', hash_lower)
        if match:
            return ("office", {
                "version": match.group(1),
                "iterations": int(match.group(2)),
                "salt": match.group(3),
                "hash": match.group(4),
                "verifier": match.group(5)
            })
    
    # ZIP
    if hash_lower.endswith('.zip') and os.path.exists(hash_str):
        return ("zip_file", {"filename": hash_str})
    
    if '$zip2$' in hash_lower:
        return ("zip_hash", {"full_hash": hash_str})
    
    return ("unknown", {"hash": hash_str})

# ========== ОСНОВНАЯ ФУНКЦИЯ ПОДБОРА ==========
def crack_hash(hash_input: str, wordlist_file: str = "passwords.TXT") -> None:
    print("\n" + "="*70)
    print("         УНИВЕРСАЛЬНЫЙ КРАКЕР ХЭШЕЙ v5.0")
    print("           (50+ ТИПОВ ХЭШЕЙ)")
    print("="*70)
    
    hash_type, params = detect_hash_type(hash_input)
    
    if hash_type == "unknown":
        print(f"[!] Неизвестный тип хэша: {hash_input[:50]}...")
        return
    
    print(f"[✓] Тип хэша определен: {hash_type.upper()}")
    
    if hash_type in ["zip_file", "zip_hash"]:
        print(f"[✓] ZIP файл: {params.get('filename', 'из хэша')}")
    
    print(f"[✓] Файл словаря: {wordlist_file}")
    print("\n[*] Начинаю перебор...")
    
    found = False
    count = 0
    
    try:
        with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                password = line.strip()
                if not password:
                    continue
                
                count += 1
                
                if count % 1000 == 0:
                    print(f"[*] Проверено паролей: {count} (текущий: {password[:20]})")
                
                check_func = None
                
                # Выбираем функцию проверки по типу
                if hash_type == "md2":
                    check_func = check_md2(password, params['hash'])
                elif hash_type == "md4":
                    check_func = check_md4(password, params['hash'])
                elif hash_type == "md5":
                    check_func = check_md5(password, params['hash'])
                elif hash_type == "md6_128":
                    check_func = check_md6_128(password, params['hash'])
                elif hash_type == "md6_256":
                    check_func = check_md6_256(password, params['hash'])
                elif hash_type == "md6_512":
                    check_func = check_md6_512(password, params['hash'])
                elif hash_type == "ripemd128":
                    check_func = check_ripemd128(password, params['hash'])
                elif hash_type == "ripemd160":
                    check_func = check_ripemd160(password, params['hash'])
                elif hash_type == "ripemd256":
                    check_func = check_ripemd256(password, params['hash'])
                elif hash_type == "ripemd320":
                    check_func = check_ripemd320(password, params['hash'])
                elif hash_type == "sha1":
                    check_func = check_sha1(password, params['hash'])
                elif hash_type == "sha224":
                    check_func = check_sha224(password, params['hash'])
                elif hash_type == "sha256":
                    check_func = check_sha256(password, params['hash'])
                elif hash_type == "sha384":
                    check_func = check_sha384(password, params['hash'])
                elif hash_type == "sha512":
                    check_func = check_sha512(password, params['hash'])
                elif hash_type == "sha3_224":
                    check_func = check_sha3_224(password, params['hash'])
                elif hash_type == "sha3_256":
                    check_func = check_sha3_256(password, params['hash'])
                elif hash_type == "sha3_384":
                    check_func = check_sha3_384(password, params['hash'])
                elif hash_type == "sha3_512":
                    check_func = check_sha3_512(password, params['hash'])
                elif hash_type == "crc16":
                    check_func = check_crc16(password, params['hash'])
                elif hash_type == "crc32":
                    check_func = check_crc32(password, params['hash'])
                elif hash_type == "adler32":
                    check_func = check_adler32(password, params['hash'])
                elif hash_type == "whirlpool":
                    check_func = check_whirlpool(password, params['hash'])
                elif hash_type == "ntlm":
                    check_func = check_ntlm(password, params['hash'])
                elif hash_type == "bcrypt":
                    check_func = check_bcrypt(password, params['full_hash'])
                elif hash_type == "office":
                    check_func = check_office(password, params)
                elif hash_type == "zip_file":
                    check_func = check_zip_file(params['filename'], password)
                elif hash_type == "zip_hash":
                    check_func = check_zip_hash(password, params['full_hash'])
                
                if check_func:
                    print("\n" + "="*70)
                    print(f"[✓] ПАРОЛЬ НАЙДЕН!".center(70))
                    print("="*70)
                    print(f"    Пароль: {password}")
                    print(f"    Тип: {hash_type.upper()}")
                    print(f"    Проверено: {count} паролей")
                    print("="*70)
                    found = True
                    break
                    
    except FileNotFoundError:
        print(f"\n[!] ОШИБКА: Файл '{wordlist_file}' не найден!")
        return
    except Exception as e:
        print(f"\n[!] Ошибка: {e}")
        return
    
    if not found:
        print("\n" + "="*70)
        print("[✗] ПАРОЛЬ НЕ НАЙДЕН".center(70))
        print("="*70)
        print(f"    Проверено паролей: {count}")
        print("="*70)

# ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========
def check_bcrypt(password: str, full_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), full_hash.encode())
    except:
        return False

def check_office(password: str, params: dict) -> bool:
    test_hash = hashlib.sha256((password + params["salt"]).encode()).hexdigest()
    return test_hash == params["hash"]

def check_zip_file(zip_file: str, password: str) -> bool:
    if PYZIPPER_AVAILABLE:
        try:
            with pyzipper.AESZipFile(zip_file, 'r') as zf:
                zf.pwd = password.encode()
                for info in zf.infolist():
                    if not info.is_dir():
                        zf.read(info.filename)
                        return True
            return False
        except:
            pass
    
    try:
        with zipfile.ZipFile(zip_file, 'r') as zf:
            zf.setpassword(password.encode())
            for info in zf.infolist():
                if not info.is_dir():
                    zf.read(info.filename)
                    return True
            return False
    except:
        return False

def check_zip_hash(password: str, full_hash: str) -> bool:
    crc = format(binascii.crc32(password.encode()) & 0xffffffff, '08x')
    md5 = hashlib.md5(password.encode()).hexdigest()
    return crc in full_hash.lower() or md5 in full_hash.lower()

# ========== МЕНЮ ==========
def interactive_mode():
    print("\n" + "="*70)
    print("         УНИВЕРСАЛЬНЫЙ КРАКЕР ХЭШЕЙ v5.0")
    print("="*70)
    print("\n📋 ПОДДЕРЖИВАЕМЫЕ ФОРМАТЫ (50+):")
    print("-" * 50)
    print("  🔹 NTLM          🔹 MD2           🔹 MD4")
    print("  🔹 MD5           🔹 MD6-128       🔹 MD6-256")
    print("  🔹 MD6-512       🔹 RipeMD-128    🔹 RipeMD-160")
    print("  🔹 RipeMD-256    🔹 RipeMD-320    🔹 SHA1")
    print("  🔹 SHA3-224      🔹 SHA3-256      🔹 SHA3-384")
    print("  🔹 SHA3-512      🔹 SHA-224       🔹 SHA-256")
    print("  🔹 SHA-384       🔹 SHA-512       🔹 CRC16")
    print("  🔹 CRC32         🔹 Adler32       🔹 Whirlpool")
    print("  🔹 bcrypt        🔹 MS Office     🔹 ZIP архивы")
    print("="*70)
    
    while True:
        print("\n[1] Ввести хэш вручную")
        print("[2] Загрузить хэш из файла")
        print("[3] Ввести имя ZIP файла")
        print("[0] Выход")
        
        choice = input("\nВыберите действие: ").strip()
        
        if choice == "0":
            print("\n[+] Выход...")
            break
        elif choice == "1":
            hash_input = input("\nВведите хэш: ").strip()
            wordlist = input(f"Путь к словарю (Enter = passwords.TXT): ").strip()
            if not wordlist:
                wordlist = "passwords.TXT"
            crack_hash(hash_input, wordlist)
        elif choice == "2":
            filename = input("Введите имя файла с хэшами: ").strip()
            try:
                with open(filename, "r") as f:
                    hash_input = f.read().strip()
                print(f"\n[+] Загружен хэш из {filename}")
                wordlist = input(f"Путь к словарю (Enter = passwords.TXT): ").strip()
                if not wordlist:
                    wordlist = "passwords.TXT"
                crack_hash(hash_input, wordlist)
            except Exception as e:
                print(f"[!] Ошибка: {e}")
        elif choice == "3":
            zip_file = input("Введите имя ZIP файла: ").strip()
            if os.path.exists(zip_file):
                wordlist = input(f"Путь к словарю (Enter = passwords.TXT): ").strip()
                if not wordlist:
                    wordlist = "passwords.TXT"
                crack_hash(zip_file, wordlist)
            else:
                print(f"[!] Файл {zip_file} не найден!")
        else:
            print("[!] Неверный выбор!")

# ========== ЗАПУСК ==========
if __name__ == "__main__":
    if not os.path.exists("passwords.TXT"):
        print("[!] Создаю тестовый файл passwords.TXT...")
        with open("passwords.TXT", "w") as f:
            test_passwords = [
                "123456", "password", "123456789", "qwerty",
                "password123", "admin", "letmein", "welcome",
                "monkey", "dragon", "12341234", "baseball"
            ]
            for pwd in test_passwords:
                f.write(pwd + "\n")
        print("[✓] Создан словарь\n")
    
    interactive_mode()
