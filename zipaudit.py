import zipfile
import io

def check_zip_real(password, zip_file):
    """Реальная проверка пароля ZIP"""
    try:
        with zipfile.ZipFile(zip_file, 'r') as zf:
            zf.setpassword(password.encode())
            # Пробуем прочитать первый файл
            zf.testzip()  # Проверяет, корректен ли пароль
            return True
    except:
        return False
