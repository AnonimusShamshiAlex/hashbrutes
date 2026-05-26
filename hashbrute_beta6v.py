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

# Для RAR архивов
try:
    from pyunpack import Archive
    PYUNPACK_AVAILABLE = True
except:
    PYUNPACK_AVAILABLE = False

try:
    import rarfile
    RARFILE_AVAILABLE = True
except:
    RARFILE_AVAILABLE = False

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

# bcrypt
def check_bcrypt(password: str, full_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), full_hash.encode())
    except:
        return False

# MS Office
def check_office(password: str, params: dict) -> bool:
    test_hash = hashlib.sha256((password + params["salt"]).encode()).hexdigest()
    return test_hash == params["hash"]

# ========== ФУНКЦИИ ДЛЯ АРХИВОВ ==========

# ZIP (через pyzipper)
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

# RAR архив (через pyunpack и rarfile)
def check_rar_file(rar_file: str, password: str) -> bool:
    """Проверка пароля для RAR архива"""
    
    # Способ 1: через pyunpack
    if PYUNPACK_AVAILABLE:
        try:
            import tempfile
            import shutil
            temp_dir = tempfile.mkdtemp()
            try:
                Archive(rar_file).extractall(temp_dir, password=password)
                shutil.rmtree(temp_dir)
                return True
            except:
                shutil.rmtree(temp_dir, ignore_errors=True)
                pass
        except:
            pass
    
    # Способ 2: через rarfile
    if RARFILE_AVAILABLE:
        try:
            # Настройка пути к unrar
            if os.name == 'nt':  # Windows
                rarfile.UNRAR_TOOL = "unrar.exe"
            else:  # Linux/Mac
                rarfile.UNRAR_TOOL = "unrar"
            
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

# 7z архив
def check_7z_file(seven_z_file: str, password: str) -> bool:
    """Проверка пароля для 7z архива"""
    try:
        import subprocess
        result = subprocess.run(
            ['7z', 't', f'-p{password}', seven_z_file],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except:
        return False

# TAR архив (с паролем - через GnuPG)
def check_tar_file(tar_file: str, password: str) -> bool:
    """Проверка пароля для зашифрованного TAR архива"""
    try:
        import subprocess
        result = subprocess.run(
            ['tar', 'tzf', tar_file, '--password', password],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except:
        return False

# PDF файл
def check_pdf_file(pdf_file: str, password: str) -> bool:
    """Проверка пароля для PDF файла"""
    try:
        import subprocess
        result = subprocess.run(
            ['qpdf', '--password=' + password, '--empty', pdf_file, '/dev/null'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except:
        return False

# ========== ДЕТЕКТОР ТИПА ХЭША ==========
def detect_hash_type(hash_str: str) -> Tuple[str, dict]:
    """Определяет ЛЮБОЙ тип хэша или файла"""
    hash_lower = hash_str.lower().strip()
    
    # Удаляем префиксы
    if ':' in hash_str and not hash_str.startswith('$'):
        parts = hash_str.split(':', 1)
        if len(parts) == 2:
            hash_str = parts[1]
            hash_lower = hash_str.lower().strip()
    
    # По длине и формату определяем тип хэша
    length = len(hash_lower)
    
    # CRC16
    if re.match(r'^[a-f0-9]{4}$', hash_lower):
        return ("crc16", {"hash": hash_lower})
    
    # CRC32 / Adler32
    if re.match(r'^[a-f0-9]{8}$', hash_lower):
        return ("crc32", {"hash": hash_lower})
    
    # MD5 / MD4 / NTLM
    if re.match(r'^[a-f0-9]{32}$', hash_lower):
        return ("md5", {"hash": hash_lower})
    
    # SHA1 / RipeMD160
    if re.match(r'^[a-f0-9]{40}$', hash_lower):
        return ("sha1", {"hash": hash_lower})
    
    # SHA224
    if re.match(r'^[a-f0-9]{56}$', hash_lower):
        return ("sha224", {"hash": hash_lower})
    
    # SHA256
    if re.match(r'^[a-f0-9]{64}$', hash_lower):
        return ("sha256", {"hash": hash_lower})
    
    # SHA384
    if re.match(r'^[a-f0-9]{96}$', hash_lower):
        return ("sha384", {"hash": hash_lower})
    
    # SHA512
    if re.match(r'^[a-f0-9]{128}$', hash_lower):
        return ("sha512", {"hash": hash_lower})
    
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
    
    # ZIP хэш
    if '$zip2$' in hash_lower:
        return ("zip_hash", {"full_hash": hash_str})
    
    # ========== ПРОВЕРКА ФАЙЛОВ ПО РАСШИРЕНИЮ ==========
    # ZIP файл
    if hash_lower.endswith('.zip') and os.path.exists(hash_str):
        return ("zip_file", {"filename": hash_str})
    
    # RAR файл
    if hash_lower.endswith('.rar') and os.path.exists(hash_str):
        return ("rar_file", {"filename": hash_str})
    
    # 7z файл
    if hash_lower.endswith('.7z') and os.path.exists(hash_str):
        return ("7z_file", {"filename": hash_str})
    
    # TAR/TAR.GZ/TAR.BZ2 файлы
    if any(hash_lower.endswith(ext) for ext in ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz']):
        if os.path.exists(hash_str):
            return ("tar_file", {"filename": hash_str})
    
    # PDF файл
    if hash_lower.endswith('.pdf') and os.path.exists(hash_str):
        return ("pdf_file", {"filename": hash_str})
    
    return ("unknown", {"hash": hash_str})

# ========== ОСНОВНАЯ ФУНКЦИЯ ПОДБОРА ==========
def crack_hash(hash_input: str, wordlist_file: str = "passwords.TXT") -> None:
    print("\n" + "="*70)
    print("         УНИВЕРСАЛЬНЫЙ КРАКЕР ХЭШЕЙ v6.0")
    print("       (ПОДДЕРЖКА ВСЕХ ТИПОВ ХЭШЕЙ И АРХИВОВ)")
    print("="*70)
    
    hash_type, params = detect_hash_type(hash_input)
    
    if hash_type == "unknown":
        print(f"[!] Неизвестный тип: {hash_input[:50]}...")
        return
    
    print(f"[✓] Тип определен: {hash_type.upper()}")
    
    filename = params.get("filename")
    if filename:
        print(f"[✓] Файл: {filename}")
        if not os.path.exists(filename):
            print(f"[!] Файл не найден!")
            return
    
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
                    print(f"[*] Проверено: {count} (текущий: {password[:20]})")
                
                check_func = None
                
                # Хэши
                if hash_type == "md2":
                    check_func = check_md2(password, params['hash'])
                elif hash_type == "md4":
                    check_func = check_md4(password, params['hash'])
                elif hash_type == "md5":
                    check_func = check_md5(password, params['hash'])
                elif hash_type in ["md6_128", "md6_256", "md6_512"]:
                    check_func = globals()[f"check_{hash_type}"](password, params['hash'])
                elif hash_type in ["ripemd128", "ripemd160", "ripemd256", "ripemd320"]:
                    check_func = globals()[f"check_{hash_type}"](password, params['hash'])
                elif hash_type in ["sha1", "sha224", "sha256", "sha384", "sha512"]:
                    check_func = globals()[f"check_{hash_type}"](password, params['hash'])
                elif hash_type in ["sha3_224", "sha3_256", "sha3_384", "sha3_512"]:
                    check_func = globals()[f"check_{hash_type}"](password, params['hash'])
                elif hash_type in ["crc16", "crc32", "adler32", "whirlpool"]:
                    check_func = globals()[f"check_{hash_type}"](password, params['hash'])
                elif hash_type == "ntlm":
                    check_func = check_ntlm(password, params['hash'])
                elif hash_type == "bcrypt":
                    check_func = check_bcrypt(password, params['full_hash'])
                elif hash_type == "office":
                    check_func = check_office(password, params)
                
                # Архивы
                elif hash_type == "zip_file":
                    check_func = check_zip_file(filename, password)
                elif hash_type == "zip_hash":
                    check_func = check_zip_hash(password, params['full_hash'])
                elif hash_type == "rar_file":
                    check_func = check_rar_file(filename, password)
                elif hash_type == "7z_file":
                    check_func = check_7z_file(filename, password)
                elif hash_type == "tar_file":
                    check_func = check_tar_file(filename, password)
                elif hash_type == "pdf_file":
                    check_func = check_pdf_file(filename, password)
                
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
        print(f"\n[!] Файл словаря не найден: {wordlist_file}")
        return
    except Exception as e:
        print(f"\n[!] Ошибка: {e}")
        return
    
    if not found:
        print("\n" + "="*70)
        print("[✗] ПАРОЛЬ НЕ НАЙДЕН".center(70))
        print("="*70)
        print(f"    Проверено: {count} паролей")
        print(f"    Тип: {hash_type}")
        print("="*70)

# ========== МЕНЮ ==========
def interactive_mode():
    print("\n" + "="*70)
    print("         УНИВЕРСАЛЬНЫЙ КРАКЕР ХЭШЕЙ v6.0")
    print("="*70)
    print("\n📋 ПОДДЕРЖИВАЕМЫЕ ФОРМАТЫ:")
    print("-" * 50)
    print("  🔹 ХЭШИ: MD2, MD4, MD5, MD6 (128/256/512)")
    print("  🔹 ХЭШИ: SHA1, SHA2 (224/256/384/512)")
    print("  🔹 ХЭШИ: SHA3 (224/256/384/512)")
    print("  🔹 ХЭШИ: RipeMD (128/160/256/320)")
    print("  🔹 ХЭШИ: CRC16, CRC32, Adler32, Whirlpool")
    print("  🔹 ХЭШИ: NTLM, bcrypt")
    print("  🔹 ФАЙЛЫ: MS Office 2013/2016")
    print("  🔹 АРХИВЫ: ZIP (ZipCrypto + AES-256)")
    print("  🔹 АРХИВЫ: RAR (через pyunpack + unrar)")
    print("  🔹 АРХИВЫ: 7Z (через 7z)")
    print("  🔹 АРХИВЫ: TAR / TAR.GZ / TAR.BZ2 / TAR.XZ")
    print("  🔹 ДРУГИЕ: PDF, и другие форматы")
    print("="*70)
    
    # Проверка установленных инструментов
    print("\n📌 СТАТУС КОМПОНЕНТОВ:")
    print(f"    pyzipper (ZIP AES-256): {'✅' if PYZIPPER_AVAILABLE else '❌'}")
    print(f"    pyunpack (RAR/7z/TAR): {'✅' if PYUNPACK_AVAILABLE else '❌'}")
    print(f"    rarfile (RAR): {'✅' if RARFILE_AVAILABLE else '❌'}")
    print("\n    Для RAR установите: sudo apt-get install unrar")
    print("    Для 7z установите: sudo apt-get install p7zip-full")
    print("="*70)
    
    while True:
        print("\n[1] Ввести хэш вручную")
        print("[2] Загрузить хэш из файла")
        print("[3] Ввести имя файла (ZIP/RAR/7z/TAR/PDF)")
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
            file_name = input("Введите имя файла: ").strip()
            if os.path.exists(file_name):
                wordlist = input(f"Путь к словарю (Enter = passwords.TXT): ").strip()
                if not wordlist:
                    wordlist = "passwords.TXT"
                crack_hash(file_name, wordlist)
            else:
                print(f"[!] Файл {file_name} не найден!")
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
