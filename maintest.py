# Сохраните как test_zip.py
import zipfile

zip_file = "photo_2026-05-25_05-50-50.zip"
password = "12341234"

try:
    with zipfile.ZipFile(zip_file, 'r') as zf:
        zf.setpassword(password.encode())
        # Пробуем прочитать первый файл
        for name in zf.namelist():
            zf.read(name)
            print(f"[✓] ПАРОЛЬ ВЕРНЫЙ: {password}")
            break
except Exception as e:
    print(f"[✗] ПАРОЛЬ НЕВЕРНЫЙ: {password}")
    print(f"Ошибка: {e}")
