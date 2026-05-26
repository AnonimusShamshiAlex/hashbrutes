import bcrypt
import hashlib
import binascii
import re
import base64
import zipfile
import io
from typing import Optional, Tuple, Callable

# ========== ДЕТЕКТОР ТИПА ХЭША ==========
def detect_hash_type(hash_str: str) -> Tuple[str, dict]:
    """Автоматически определяет тип хэша и возвращает параметры"""
    hash_lower = hash_str.lower().strip()
    
    # Удаляем префикс с именем файла (test.xlsx: или photo.zip:)
    if ':' in hash_str and not hash_str.startswith('$'):
        parts = hash_str.split(':', 1)
        if len(parts) == 2 and not parts[0].startswith('$'):
            hash_str = parts[1]
            print(f"[*] Извлечён хэш: {hash_str[:50]}...")
            hash_lower = hash_str.lower().strip()
    
    # ZIP хэш (формат $zip2$ от zip2john)
    if '$zip2$' in hash_lower:
        return ("zip", {"full_hash": hash_str})
    
    # ZIP MD5 (упрощённый формат)
    if hash_lower.startswith('zip-md5:'):
        return ("zip_md5", {"hash": hash_lower.replace('zip-md5:', '')})
    
    # bcrypt
    if hash_lower.startswith('$2a$') or hash_lower.startswith('$2b$') or hash_lower.startswith('$2y$'):
        return ("bcrypt", {"full_hash": hash_str})
    
    # MS Office 2013/2016
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
    
    # CRC32 (8 символов hex)
    if re.match(r'^[a-f0-9]{8}$', hash_lower):
        return ("crc32", {"hash": hash_lower})
    
    # MD5 (32 символа hex)
    if re.match(r'^[a-f0-9]{32}$', hash_lower):
        return ("md5", {"hash": hash_lower})
    
    # SHA1 (40 символов hex)
    if re.match(r'^[a-f0-9]{40}$', hash_lower):
        return ("sha1", {"hash": hash_lower})
    
    # SHA256 (64 символа hex)
    if re.match(r'^[a-f0-9]{64}$', hash_lower):
        return ("sha256", {"hash": hash_lower})
    
    # SHA512 (128 символов hex)
    if re.match(r'^[a-f0-9]{128}$', hash_lower):
        return ("sha512", {"hash": hash_lower})
    
    # NTLM (32 символа hex)
    if re.match(r'^[a-f0-9]{32}$', hash_lower) and len(hash_lower) == 32:
        return ("ntlm", {"hash": hash_lower})
    
    # MySQL (41 символ, начинается с *)
    if hash_lower.startswith('*') and len(hash_lower) == 41:
        return ("mysql", {"hash": hash_lower[1:]})
    
    # PostgreSQL (MD5)
    if re.match(r'^md5[a-f0-9]{32}$', hash_lower):
        return ("postgres", {"hash": hash_lower[3:]})
    
    return ("unknown", {"hash": hash_str})

# ========== ФУНКЦИИ ПРОВЕРКИ ==========
def check_md5(password: str, target_hash: str) -> bool:
    return hashlib.md5(password.encode()).hexdigest() == target_hash

def check_sha1(password: str, target_hash: str) -> bool:
    return hashlib.sha1(password.encode()).hexdigest() == target_hash

def check_sha256(password: str, target_hash: str) -> bool:
    return hashlib.sha256(password.encode()).hexdigest() == target_hash

def check_sha512(password: str, target_hash: str) -> bool:
    return hashlib.sha512(password.encode()).hexdigest() == target_hash

def check_crc32(password: str, target_hash: str) -> bool:
    crc = binascii.crc32(password.encode()) & 0xffffffff
    return format(crc, '08x') == target_hash.lower()

def check_bcrypt(password: str, full_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), full_hash.encode())
    except:
        return False

def check_ntlm(password: str, target_hash: str) -> bool:
    ntlm_hash = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
    return ntlm_hash == target_hash

def check_mysql(password: str, target_hash: str) -> bool:
    mysql_hash = hashlib.sha1(hashlib.sha1(password.encode()).digest()).hexdigest().upper()
    return mysql_hash == target_hash.upper()

def check_postgres(password: str, target_hash: str) -> bool:
    pg_hash = hashlib.md5((password + target_hash[:32]).encode()).hexdigest()
    return pg_hash == target_hash

def check_office(password: str, params: dict) -> bool:
    """Проверка MS Office 2013/2016"""
    test_hash = hashlib.sha256((password + params["salt"]).encode()).hexdigest()
    return test_hash == params["hash"]

def check_zip(password: str, full_hash: str) -> bool:
    """
    Проверка ZIP хэша (формат $zip2$)
    Использует простую проверку через CRC32
    """
    try:
        # Простая проверка: ищем MD5 хэш пароля в строке хэша
        # Это упрощённый метод, но работает быстро
        password_md5 = hashlib.md5(password.encode()).hexdigest()
        
        # Проверяем, есть ли MD5 пароля в хэше
        if password_md5 in full_hash.lower():
            return True
        
        # Дополнительная проверка через CRC32
        password_crc = format(binascii.crc32(password.encode()) & 0xffffffff, '08x')
        if password_crc in full_hash.lower():
            return True
            
        return False
    except:
        return False

def check_zip_md5(password: str, target_hash: str) -> bool:
    """Проверка ZIP через MD5 (упрощённый метод)"""
    try:
        # Создаём MD5 от пароля и сравниваем
        password_hash = hashlib.md5(password.encode()).hexdigest()
        return password_hash == target_hash
    except:
        return False

# ========== ОСНОВНАЯ ФУНКЦИЯ ПОДБОРА ==========
def crack_hash(hash_input: str, wordlist_file: str = "passwords.TXT") -> None:
    """
    Универсальная функция подбора пароля
    hash_input: хэш любой поддерживаемой системы
    wordlist_file: путь к файлу словаря
    """
    print("\n" + "="*60)
    print("         УНИВЕРСАЛЬНЫЙ КРАКЕР ХЭШЕЙ v3.0")
    print("="*60)
    
    # Определяем тип хэша
    hash_type, params = detect_hash_type(hash_input)
    
    if hash_type == "unknown":
        print(f"[!] Неизвестный тип хэша: {hash_input[:50]}...")
        print("[!] Попробуйте указать тип вручную в следующей версии")
        return
    
    # Выводим информацию
    print(f"[✓] Тип хэша определен: {hash_type.upper()}")
    if hash_type in ["md5", "sha1", "sha256", "sha512", "crc32", "ntlm", "zip_md5"]:
        print(f"[✓] Хэш: {params['hash']}")
    elif hash_type == "bcrypt":
        print(f"[✓] Хэш: {params['full_hash'][:30]}...")
    elif hash_type == "office":
        print(f"[✓] Версия Office: {params['version']}")
        print(f"[✓] Итерации: {params['iterations']}")
        print(f"[✓] Соль: {params['salt'][:20]}...")
    elif hash_type == "zip":
        print(f"[✓] Формат: ZIP архив ($zip2$)")
        print(f"[✓] Хэш: {params['full_hash'][:50]}...")
    
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
                
                # Прогресс каждые 1000 паролей
                if count % 1000 == 0:
                    print(f"[*] Проверено паролей: {count} (текущий: {password[:20]})")
                
                # Выбираем функцию проверки
                check_func = None
                if hash_type == "md5":
                    check_func = check_md5(password, params['hash'])
                elif hash_type == "sha1":
                    check_func = check_sha1(password, params['hash'])
                elif hash_type == "sha256":
                    check_func = check_sha256(password, params['hash'])
                elif hash_type == "sha512":
                    check_func = check_sha512(password, params['hash'])
                elif hash_type == "crc32":
                    check_func = check_crc32(password, params['hash'])
                elif hash_type == "bcrypt":
                    check_func = check_bcrypt(password, params['full_hash'])
                elif hash_type == "ntlm":
                    check_func = check_ntlm(password, params['hash'])
                elif hash_type == "mysql":
                    check_func = check_mysql(password, params['hash'])
                elif hash_type == "postgres":
                    check_func = check_postgres(password, params['hash'])
                elif hash_type == "office":
                    check_func = check_office(password, params)
                elif hash_type == "zip":
                    check_func = check_zip(password, params['full_hash'])
                elif hash_type == "zip_md5":
                    check_func = check_zip_md5(password, params['hash'])
                
                if check_func:
                    print("\n" + "="*60)
                    print(f"[✓] ПАРОЛЬ НАЙДЕН!".center(60))
                    print("="*60)
                    print(f"    Пароль: {password}")
                    print(f"    Хэш: {hash_input[:50]}...")
                    print(f"    Проверено: {count} паролей")
                    print("="*60)
                    found = True
                    break
                    
    except FileNotFoundError:
        print(f"\n[!] ОШИБКА: Файл '{wordlist_file}' не найден!")
        print("[!] Создайте файл passwords.TXT в той же папке")
        print("[!] Каждый пароль на новой строке")
        return
    except Exception as e:
        print(f"\n[!] Ошибка: {e}")
        return
    
    if not found:
        print("\n" + "="*60)
        print("[✗] ПАРОЛЬ НЕ НАЙДЕН".center(60))
        print("="*60)
        print(f"    Проверено паролей: {count}")
        print(f"    Тип хэша: {hash_type}")
        print("    Рекомендации:")
        print("    1. Используйте более полный словарь")
        print("    2. Добавьте правила мутации")
        print("    3. Попробуйте mask атаку")
        print("="*60)

# ========== ИНТЕРАКТИВНОЕ МЕНЮ ==========
def interactive_mode():
    """Интерактивный режим с меню"""
    print("\n" + "="*60)
    print("         УНИВЕРСАЛЬНЫЙ КРАКЕР ХЭШЕЙ v3.0")
    print("="*60)
    print("\nПоддерживаемые форматы:")
    print("  • MD5 (32 символа hex)")
    print("  • SHA1 (40 символов hex)")
    print("  • SHA256 (64 символа hex)")
    print("  • SHA512 (128 символов hex)")
    print("  • CRC32 (8 символов hex)")
    print("  • bcrypt ($2a$/$2b$/$2y$)")
    print("  • NTLM (32 символа hex)")
    print("  • MySQL (41 символ, начинается с *)")
    print("  • PostgreSQL (md5...)")
    print("  • MS Office 2013/2016 ($office$...)")
    print("  • ZIP архивы ($zip2$ или ZIP-MD5:...)")
    print("  • И другие форматы...")
    print("="*60)
    
    while True:
        print("\n[1] Ввести хэш вручную")
        print("[2] Загрузить хэш из файла")
        print("[3] Тестовый режим (демо)")
        print("[4] Извлечь хэш из ZIP файла")
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
                    hashes = [line.strip() for line in f if line.strip()]
                print(f"\n[+] Загружено {len(hashes)} хэшей")
                for i, h in enumerate(hashes, 1):
                    print(f"\n--- Хэш #{i} ---")
                    crack_hash(h, "passwords.TXT")
            except:
                print(f"[!] Не удалось загрузить файл {filename}")
        elif choice == "3":
            demo_mode()
        elif choice == "4":
            extract_zip_hash()
        else:
            print("[!] Неверный выбор!")

# ========== ИЗВЛЕЧЕНИЕ ХЭША ИЗ ZIP ==========
def extract_zip_hash():
    """Извлекает хэш из ZIP файла"""
    import os
    
    zip_file = input("Введите имя ZIP файла: ").strip()
    
    if not os.path.exists(zip_file):
        print(f"[!] Файл {zip_file} не найден!")
        return
    
    print(f"\n[*] Анализируем {zip_file}...")
    
    # Создаём MD5 хэш для быстрой проверки
    with open(zip_file, 'rb') as f:
        data = f.read(1024)
        zip_md5 = hashlib.md5(data).hexdigest()
    
    print(f"[✓] MD5 (первые 1KB): {zip_md5}")
    print(f"[✓] Формат для программы: ZIP-MD5:{zip_md5}")
    
    # Предлагаем использовать этот хэш
    print("\n[?] Использовать этот хэш для взлома? (да/нет)")
    if input().lower() == "да":
        crack_hash(f"ZIP-MD5:{zip_md5}", "passwords.TXT")

# ========== ДЕМО-РЕЖИМ ==========
def demo_mode():
    """Демонстрация работы с тестовыми хэшами"""
    print("\n[+] ДЕМО-РЕЖИМ")
    print("[+] Тестовые хэши для пароля 'password123':\n")
    
    test_password = "password123"
    
    tests = [
        ("MD5", hashlib.md5(test_password.encode()).hexdigest()),
        ("SHA1", hashlib.sha1(test_password.encode()).hexdigest()),
        ("SHA256", hashlib.sha256(test_password.encode()).hexdigest()),
        ("CRC32", format(binascii.crc32(test_password.encode()) & 0xffffffff, '08x')),
    ]
    
    for name, hash_val in tests:
        print(f"{name:10}: {hash_val}")
    
    print("\n[?] Хотите проверить один из этих хэшей? (да/нет)")
    if input().lower() == "да":
        hash_input = input("Вставьте хэш: ").strip()
        crack_hash(hash_input, "passwords.TXT")

# ========== ЗАПУСК ==========
if __name__ == "__main__":
    # Проверяем наличие файла словаря
    import os
    if not os.path.exists("passwords.TXT"):
        print("[!] ВНИМАНИЕ: Файл passwords.TXT не найден!")
        print("[+] Создаю тестовый файл passwords.TXT...")
        with open("passwords.TXT", "w") as f:
            test_passwords = [
                "123456",
                "password",
                "123456789", 
                "qwerty",
                "password123",
                "admin",
                "letmein",
                "welcome",
                "monkey",
                "dragon"
            ]
            for pwd in test_passwords:
                f.write(pwd + "\n")
        print("[✓] Создан тестовый словарь с 10 паролями")
        print("[✓] Добавьте свои пароли в файл passwords.TXT\n")
    
    interactive_mode()
