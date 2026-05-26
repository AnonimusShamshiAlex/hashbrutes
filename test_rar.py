# test_rar.py
import subprocess

rar_file = input("ваш_файл.rar:")
password = input("parol:")

# Пробуем unrar
print("Тест unrar:")
result = subprocess.run(['unrar', 't', '-p' + password, rar_file], 
                       capture_output=True, text=True)
print(f"Код: {result.returncode}")
print(result.stdout[:200])

# Пробуем 7z
print("\nТест 7z:")
result = subprocess.run(['7z', 't', '-p' + password, rar_file], 
                       capture_output=True, text=True)
print(f"Код: {result.returncode}")
