from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# Функция для побитовой операции XOR двух байтовых строк
def xor_bytes(a, b):
    return bytes(i ^ j for i, j in zip(a, b))

# Функция шифрования с использованием алгоритма AES в режиме OFB (Output Feedback)
def aes_ofb_encrypt(plaintext, key, iv):
    # Инициализация AES-шифра в режиме ECB (для формирования потока ключа)
    cipher = AES.new(key, AES.MODE_ECB)
    key_stream = iv  # Инициализационный вектор будет начальным значением потока ключа
    ciphertext = b''  # Переменная для хранения зашифрованного текста

    # Процесс шифрования блоками по 16 байт
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        key_stream = cipher.encrypt(key_stream)  # Генерация следующего блока потока ключа
        encrypted_block = xor_bytes(block, key_stream[:len(block)])  # XOR с потоком ключа
        ciphertext += encrypted_block  # Добавление зашифрованного блока в итоговый шифротекст

    return iv + ciphertext  # Возвращаем IV + зашифрованный текст

# Функция расшифровки с использованием AES в режиме OFB
def aes_ofb_decrypt(ciphertext, key):
    iv = ciphertext[:16]  # Извлечение IV из начала шифротекста
    ciphertext = ciphertext[16:]  # Убираем IV из основного шифротекста
    cipher = AES.new(key, AES.MODE_ECB)  # Инициализация AES-шифра в режиме ECB
    key_stream = iv  # Инициализация потока ключа IV
    plaintext = b''  # Переменная для хранения расшифрованного текста

    # Процесс расшифрования блоками по 16 байт
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        key_stream = cipher.encrypt(key_stream)  # Генерация следующего блока потока ключа
        decrypted_block = xor_bytes(block, key_stream[:len(block)])  # XOR с потоком ключа
        plaintext += decrypted_block  # Добавление расшифрованного блока в итоговый текст

    return plaintext  # Возвращаем расшифрованный текст

# Функция для чтения данных из файла
def read_file(filename):
    with open(filename, "rb") as f:
        return f.read()

# Функция для записи данных в файл
def write_file(filename, data):
    with open(filename, "wb") as f:
        f.write(data)

# Функция для парсинга файлов формата .rsp (например, тестовых векторов для NIST)
def parse_rsp_file(filename):
    test_vectors = []  # Список для хранения тестовых векторов
    current_test = {}  # Словарь для текущего теста

    # Чтение файла построчно
    with open(filename, "r") as f:
        for line in f:
            line = line.strip()  # Убираем лишние пробелы
            if line.startswith("#") or not line:
                continue  # Пропускаем комментарии и пустые строки
            if line.startswith("COUNT"):
                if current_test:
                    test_vectors.append(current_test)  # Добавляем текущий тест в список
                    current_test = {}  # Очищаем словарь для нового теста
            if "=" in line:
                key, value = line.split("=")  # Разделяем строку на ключ и значение
                key = key.strip().lower()  # Приводим ключ к нижнему регистру
                value = value.strip()  # Убираем лишние пробелы из значения
                current_test[key] = value  # Добавляем пару ключ-значение в текущий тест

        if current_test:
            test_vectors.append(current_test)  # Добавляем последний тест

    return test_vectors  # Возвращаем список всех тестов

# Функция для отладочной печати тестовых векторов
def debug_print_vector(vectors):
    for i, test in enumerate(vectors):
        print(f"Vector {i + 1}:")
        for key, value in test.items():
            print(f"{key}: {value}")
        print()

# Функция для выполнения тестов NIST для проверки правильности шифрования/расшифрования
def run_nist_tests():
    test_vectors = parse_rsp_file("OFBVarTxt256.rsp")  # Парсим тестовые векторы из файла

    for test in test_vectors:
        key = bytes.fromhex(test["key"])  # Преобразуем ключ из hex в байты
        iv = bytes.fromhex(test["iv"])  # Преобразуем IV из hex в байты
        
        if "plaintext" in test:
            plaintext = bytes.fromhex(test["plaintext"])  # Преобразуем plaintext из hex
            expected_ciphertext = bytes.fromhex(test["ciphertext"])  # Ожидаемый шифротекст
            ciphertext = aes_ofb_encrypt(plaintext, key, iv)  # Шифруем plaintext
            ciphertext = ciphertext[16:]  # Убираем IV из результата
            # Проверяем, совпадает ли полученный шифротекст с ожидаемым
            assert ciphertext == expected_ciphertext, f"Encryption failed for test: {test}"
        
        if "ciphertext" in test and "plaintext" in test:
            ciphertext = bytes.fromhex(test["ciphertext"])  # Преобразуем ciphertext из hex
            expected_plaintext = bytes.fromhex(test["plaintext"])  # Ожидаемый plaintext
            decrypted = aes_ofb_decrypt(iv + ciphertext, key)  # Расшифровываем с добавленным IV
            # Проверяем, совпадает ли полученный plaintext с ожидаемым
            assert decrypted == expected_plaintext, f"Decryption failed for test: {test}"
    
    print("All NIST test vectors passed.")  # Все тесты прошли успешно

# Основная функция программы
def main():
    key = os.urandom(32)  # Генерация случайного 32-байтового ключа
    iv = os.urandom(16)  # Генерация случайного 16-байтового IV

    # Чтение и подготовка данных (для примера, файл input)
    plaintext = read_file("input")
    plaintext = pad(plaintext, 16)  # Дополнение до 16 байт

    ciphertext = aes_ofb_encrypt(plaintext, key, iv)  # Шифрование данных
    print("Encrypted:", ciphertext.hex())  # Выводим зашифрованный текст в hex

    write_file("encrypted", ciphertext)  # Сохраняем зашифрованный текст в файл

    ciphertext = read_file("encrypted")  # Чтение зашифрованного текста из файла

    decrypted = aes_ofb_decrypt(ciphertext, key)  # Расшифровка
    decrypted = unpad(decrypted, 16)  # Убираем дополнение
    print("Decrypted:", decrypted.decode())  # Выводим расшифрованный текст

    run_nist_tests()  # Запуск тестов NIST для проверки реализации

# Запуск основной функции, если файл был запущен напрямую
if __name__ == "__main__":
    main()
