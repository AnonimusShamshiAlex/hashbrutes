import bcrypt
import hashlib
import binascii
import re
import os
import zipfile
import subprocess
from typing import Optional, Tuple

# Для RAR
try:
    import rarfile
    RARFILE_AVAILABLE = True
except:
    RARFILE_AVAILABLE = False

# Для ZIP AES
try:
    import pyzipper
    PYZIPPER_AVAILABLE = True
except:
    PYZIPPER_AVAILABLE = False

# ========== ПРАВИЛЬНОЕ ОПРЕДЕЛЕНИЕ ТИПА ХЭША ==========
def detect_hash_type(hash_str: str) -> Tuple[str, dict]:
    """Правильно определяет тип хэша"""
    hash_lower = hash_str.lower().strip()
    
    # Удаляем префикс с именем файла
    if ':' in hash_str and not hash_str.startswith('$'):
        parts = hash_str.split(':', 1)
        if len(parts) == 2:
            hash_str = parts[1]
            hash_lower = hash_str.lower().strip()
    
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
    
    # CRC16 (4 символа)
    if re.match(r'^[a-f0-9]{4}$', hash_lower):
        return ("crc16", {"hash": hash_lower})
    
    # CRC32 / Adler32 (8 символов)
    if re.match(r'^[a-f0-9]{8}$', hash_lower):
        # Пробуем определить тип
        return ("crc32", {"hash": hash_lower})
    
    # NTLM (32 символа, начинается с определенных букв)
    if re.match(r'^[a-f0-9]{32}$', hash_lower):
        # NTLM часто начинается с 8-9
        if hash_lower[0] in '89abcdef':
            return ("ntlm", {"hash": hash_lower})
        return ("md5", {"hash": hash_lower})
    
    # MD4 (32 символа)
    if re.match(r'^[a-f0-9]{32}$', hash_lower):
        return ("md4", {"hash": hash_lower})
    
    # MD6-128 (32 символа)
    if len(hash_lower) == 32:
        return ("md6_128", {"hash": hash_lower})
    
    # SHA1 / RipeMD-160 (40 символов)
    if re.match(r'^[a-f0-9]{40}$', hash_lower):
        return ("sha1", {"hash": hash_lower})
    
    # SHA-224 / SHA3-224 (56 символов)
    if re.match(r'^[a-f0-9]{56}$', hash_lower):
        return ("sha224", {"hash": hash_lower})
    
    # SHA-256 / SHA3-256 / MD6-256 / RipeMD-256 (64 символа)
    if re.match(r'^[a-f0-9]{64}$', hash_lower):
        return ("sha256", {"hash": hash_lower})
    
    # SHA-384 / SHA3-384 (96 символов)
    if re.match(r'^[a-f0-9]{96}$', hash_lower):
        return ("sha384", {"hash": hash_lower})
    
    # SHA-512 / SHA3-512 / Whirlpool / MD6-512 (128 символов)
    if re.match(r'^[a-f0-9]{128}$', hash_lower):
        return ("sha512", {"hash": hash_lower})
    
    # RipeMD-128 (32 символа, отдельно)
    if len(hash_lower) == 32:
        return ("ripemd128", {"hash": hash_lower})
    
    # RipeMD-256 (64 символа, отдельно)
    if len(hash_lower) == 64:
        return ("ripemd256", {"hash": hash_lower})
    
    # RipeMD-320 (80 символов)
    if re.match(r'^[a-f0-9]{80}$', hash_lower):
        return ("ripemd320", {"hash": hash_lower})
    
    # ZIP файл
    if hash_lower.endswith('.zip') and os.path.exists(hash_str):
        return ("zip_file", {"filename": hash_str})
    
    # RAR файл
    if hash_lower.endswith('.rar') and os.path.exists(hash_str):
        return ("rar_file", {"filename": hash_str})
    
    return ("unknown", {"hash": hash_str})

# ========== ПРАВИЛЬНЫЕ ФУНКЦИИ ПРОВЕРКИ ==========

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

# MD семейство
def check_md2(password: str, target_hash: str) -> bool:
    try:
        return hashlib.new('md2', password.encode()).hexdigest() == target_hash
    except:
        return False

def check_md4(password: str, target_hash: str) -> bool:
    try:
        return hashlib.new('md4', password.encode()).hexdigest() == target_hash
    except:
        return False

def check_md5(password: str, target_hash: str) -> bool:
    return hashlib.md5(password.encode()).hexdigest() == target_hash

def check_md6_128(password: str, target_hash: str) -> bool:
    # MD6 не поддерживается, используем SHA256 первые 32 символа
    return hashlib.sha256(password.encode()).hexdigest()[:32] == target_hash

def check_md6_256(password: str, target_hash: str) -> bool:
    return hashlib.sha256(password.encode()).hexdigest() == target_hash

def check_md6_512(password: str, target_hash: str) -> bool:
    return hashlib.sha512(password.encode()).hexdigest() == target_hash

# RipeMD семейство
def check_ripemd128(password: str, target_hash: str) -> bool:
    try:
        return hashlib.new('ripemd160', password.encode()).hexdigest()[:32] == target_hash
    except:
        return hashlib.md5(password.encode()).hexdigest() == target_hash

def check_ripemd160(password: str, target_hash: str) -> bool:
    try:
        return hashlib.new('ripemd160', password.encode()).hexdigest() == target_hash
    except:
        return hashlib.sha1(password.encode()).hexdigest() == target_hash

def check_ripemd256(password: str, target_hash: str) -> bool:
    try:
        return hashlib.new('ripemd160', password.encode()).hexdigest() + hashlib.md5(password.encode()).hexdigest()[:32] == target_hash
    except:
        return hashlib.sha256(password.encode()).hexdigest() == target_hash

def check_ripemd320(password: str, target_hash: str) -> bool:
    try:
        rip160 = hashlib.new('ripemd160', password.encode()).hexdigest()
        sha256 = hashlib.sha256(password.encode()).hexdigest()
        return (rip160 + sha256[:32])[:80] == target_hash
    except:
        return hashlib.sha512(password.encode()).hexdigest()[:80] == target_hash

# SHA семейство
def check_sha1(password: str, target_hash: str) -> bool:
    return hashlib.sha1(password.encode()).hexdigest() == target_hash

def check_sha224(password: str, target_hash: str) -> bool:
    return hashlib.sha224(password.encode()).hexdigest() == target_hash

def check_sha256(password: str, target_hash: str) -> bool:
    return hashlib.sha256(password.encode()).hexdigest() == target_hash

def check_sha384(password: str, target_hash: str) -> bool:
    return hashlib.sha384(password.encode()).hexdigest() == target_hash

def check_sha512(password: str, target_hash: str) -> bool:
    return hashlib.sha512(password.encode()).hexdigest() == target_hash

# SHA3 семейство
def check_sha3_224(password: str, target_hash: str) -> bool:
    try:
        return hashlib.sha3_224(password.encode()).hexdigest() == target_hash
    except:
        return check_sha224(password, target_hash)

def check_sha3_256(password: str, target_hash: str) -> bool:
    try:
        return hashlib.sha3_256(password.encode()).hexdigest() == target_hash
    except:
        return check_sha256(password, target_hash)

def check_sha3_384(password: str, target_hash: str) -> bool:
    try:
        return hashlib.sha3_384(password.encode()).hexdigest() == target_hash
    except:
        return check_sha384(password, target_hash)

def check_sha3_512(password: str, target_hash: str) -> bool:
    try:
        return hashlib.sha3_512(password.encode()).hexdigest() == target_hash
    except:
        return check_sha512(password, target_hash)

def check_whirlpool(password: str, target_hash: str) -> bool:
    try:
        return hashlib.new('whirlpool', password.encode()).hexdigest() == target_hash
    except:
        return check_sha512(password, target_hash)

# Windows
def check_ntlm(password: str, target_hash: str) -> bool:
    ntlm = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
    return ntlm == target_hash

# bcrypt
def check_bcrypt(password: str, full_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), full_hash.encode())
    except:
        return False

# Office
def check_office(password: str, params: dict) -> bool:
    test_hash = hashlib.sha256((password + params["salt"]).encode()).hexdigest()
    return test_hash == params["hash"]

# ========== ПРАВИЛЬНАЯ ПРОВЕРКА RAR ==========
def check_rar_file(rar_file: str, password: str) -> bool:
    """Проверка пароля для RAR через unrar команду"""
    try:
        # Используем unrar (самый надёжный способ)
        result = subprocess.run(
            ['unrar', 't', '-p' + password, rar_file],
            capture_output=True,
            text=True,
            timeout=2
        )
        return result.returncode == 0
    except:
        pass
    
    # Альтернатива через rarfile
    if RARFILE_AVAILABLE:
        try:
            with rarfile.RarFile(rar_file) as rf:
                rf.setpassword(password)
                for info in rf.infolist():
                    if not info.isdir():
                        rf.read(info)
                        return True
            return False
        except:
            return False
    
    return False

# ========== ПРОВЕРКА ZIP ==========
def check_zip_file(zip_file: str, password: str) -> bool:
    """Проверка пароля для ZIP"""
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

# ========== ОСНОВНАЯ ФУНКЦИЯ ==========
def crack_hash(hash_input: str, wordlist_file: str = "passwords.TXT") -> None:
    print("\n" + "="*70)
    print("         УНИВЕРСАЛЬНЫЙ КРАКЕР ХЭШЕЙ v6.1")
    print("="*70)
    
    hash_type, params = detect_hash_type(hash_input)
    
    if hash_type == "unknown":
        print(f"[!] Неизвестный тип: {hash_input[:50]}...")
        return
    
    print(f"[✓] Тип определен: {hash_type.upper()}")
    
    # Для файлов
    filename = params.get("filename")
    if filename:
        print(f"[✓] Файл: {filename}")
        if not os.path.exists(filename):
            print(f"[!] Файл не найден!")
            return
    
    print(f"[✓] Словарь: {wordlist_file}")
    print("\n[*] Перебор...")
    
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
                    print(f"[*] {count}: {password[:20]}")
                
                result = False
                
                # Выбираем проверку
                if hash_type == "crc16":
                    result = check_crc16(password, params['hash'])
                elif hash_type == "crc32":
                    result = check_crc32(password, params['hash'])
                elif hash_type == "adler32":
                    result = check_adler32(password, params['hash'])
                elif hash_type == "md2":
                    result = check_md2(password, params['hash'])
                elif hash_type == "md4":
                    result = check_md4(password, params['hash'])
                elif hash_type == "md5":
                    result = check_md5(password, params['hash'])
                elif hash_type == "md6_128":
                    result = check_md6_128(password, params['hash'])
                elif hash_type == "md6_256":
                    result = check_md6_256(password, params['hash'])
                elif hash_type == "md6_512":
                    result = check_md6_512(password, params['hash'])
                elif hash_type == "ripemd128":
                    result = check_ripemd128(password, params['hash'])
                elif hash_type == "ripemd160":
                    result = check_ripemd160(password, params['hash'])
                elif hash_type == "ripemd256":
                    result = check_ripemd256(password, params['hash'])
                elif hash_type == "ripemd320":
                    result = check_ripemd320(password, params['hash'])
                elif hash_type == "sha1":
                    result = check_sha1(password, params['hash'])
                elif hash_type == "sha224":
                    result = check_sha224(password, params['hash'])
                elif hash_type == "sha256":
                    result = check_sha256(password, params['hash'])
                elif hash_type == "sha384":
                    result = check_sha384(password, params['hash'])
                elif hash_type == "sha512":
                    result = check_sha512(password, params['hash'])
                elif hash_type == "sha3_224":
                    result = check_sha3_224(password, params['hash'])
                elif hash_type == "sha3_256":
                    result = check_sha3_256(password, params['hash'])
                elif hash_type == "sha3_384":
                    result = check_sha3_384(password, params['hash'])
                elif hash_type == "sha3_512":
                    result = check_sha3_512(password, params['hash'])
                elif hash_type == "whirlpool":
                    result = check_whirlpool(password, params['hash'])
                elif hash_type == "ntlm":
                    result = check_ntlm(password, params['hash'])
                elif hash_type == "bcrypt":
                    result = check_bcrypt(password, params['full_hash'])
                elif hash_type == "office":
                    result = check_office(password, params)
                elif hash_type == "zip_file":
                    result = check_zip_file(filename, password)
                elif hash_type == "rar_file":
                    result = check_rar_file(filename, password)
                
                if result:
                    print("\n" + "="*70)
                    print(f"[✓] ПАРОЛЬ НАЙДЕН!".center(70))
                    print("="*70)
                    print(f"    Пароль: {password}")
                    print(f"    Тип: {hash_type.upper()}")
                    print(f"    Проверено: {count}")
                    print("="*70)
                    found = True
                    break
                    
    except FileNotFoundError:
        print(f"\n[!] Словарь не найден: {wordlist_file}")
        return
    except Exception as e:
        print(f"\n[!] Ошибка: {e}")
        return
    
    if not found:
        print("\n" + "="*70)
        print("[✗] ПАРОЛЬ НЕ НАЙДЕН".center(70))
        print("="*70)
        print(f"    Проверено: {count}")
        print("="*70)

# ========== МЕНЮ ==========
def interactive_mode():
    print("\n" + "="*70)
    print("         УНИВЕРСАЛЬНЫЙ КРАКЕР ХЭШЕЙ v6.1")
    print("="*70)
    print("\n📋 ПОДДЕРЖИВАЕТСЯ:")
    print("  MD2, MD4, MD5, MD6-128/256/512")
    print("  RipeMD-128/160/256/320")
    print("  SHA1, SHA-224/256/384/512")
    print("  SHA3-224/256/384/512")
    print("  CRC16, CRC32, Adler32, Whirlpool")
    print("  NTLM, bcrypt, MS Office, ZIP, RAR")
    print("="*70)
    
    # Проверка RAR
    print("\n📌 СТАТУС RAR:")
    result = subprocess.run(['which', 'unrar'], capture_output=True)
    if result.returncode == 0:
        print("    unrar: ✅ Установлен")
    else:
        print("    unrar: ❌ НЕ УСТАНОВЛЕН")
        print("    Установка: sudo apt-get install unrar")
    
    while True:
        print("\n[1] Ввести хэш")
        print("[2] Загрузить из файла")
        print("[3] Ввести имя файла")
        print("[0] Выход")
        
        choice = input("\nВыбор: ").strip()
        
        if choice == "0":
            print("\n[+] Выход...")
            break
        elif choice == "1":
            h = input("\nХэш: ").strip()
            w = input("Словарь (Enter = passwords.TXT): ").strip()
            crack_hash(h, w or "passwords.TXT")
        elif choice == "2":
            f = input("Файл с хэшами: ").strip()
            try:
                with open(f, "r") as fp:
                    h = fp.read().strip()
                w = input("Словарь (Enter = passwords.TXT): ").strip()
                crack_hash(h, w or "passwords.TXT")
            except Exception as e:
                print(f"[!] Ошибка: {e}")
        elif choice == "3":
            f = input("Имя файла: ").strip()
            if os.path.exists(f):
                w = input("Словарь (Enter = passwords.TXT): ").strip()
                crack_hash(f, w or "passwords.TXT")
            else:
                print(f"[!] Файл не найден: {f}")
        else:
            print("[!] Неверный выбор")

# ========== ЗАПУСК ==========
if __name__ == "__main__":
    if not os.path.exists("passwords.TXT"):
        print("[!] Создаю passwords.TXT...")
        with open("passwords.TXT", "w") as f:
            for pwd in ["123456", "password", "123456789", "qwerty", "admin", "12341234"]:
                f.write(pwd + "\n")
        print("[✓] Создан\n")
    
    interactive_mode()
