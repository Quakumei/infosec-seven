"""

EAX/AEAD  (Encrypt-then-Authenticate-then-Translate) – двухпроходный алгоритм с
ассоциированными данными  AEAD, где первый проход выполняется для достижения
конфиденциальности, а второй для достижения аутентификации каждого блока. Для
шифрования используется режим CTR, а для аутентификации OMAC (One Key MAC) над
каждым блоком применяется метода композиции EAX.

🔐 AEAD (Authenticated Encryption with Associated Data)
Это криптографическая концепция, не алгоритм.
Она обозначает шифрование, при котором:

Данные шифруются и аутентифицируются одновременно
Можно передать дополнительные данные (Associated Data), которые не шифруются, но проверяются на целостность (например, заголовки пакетов)
Примеры AEAD-алгоритмов:

- AES-GCM
- ChaCha20-Poly1305
- EAX

🔐 EAX
Это конкретный AEAD-режим блочного шифра, основанный на AES.

Характеристики:
Работает с блочными шифрами (чаще всего AES)
Не патентован
Безопасен при правильной реализации


Для режимов необходимо вручную применять процесс шифрования/дешифрования 
AES (SubBytes, ShiftRows, MixColomns, ...), для первого алгоритма необходимые шаги 
указаны, для последующих опущены для краткости

Алгоритм EСB
Шифрование:
Необходимо сгенерировать раундовые ключи
Добавить паддинг, дополняя данные до кратного 16 размера, например 
PKCS7
Выполнить разделение на блоки по 16 байт
Зашифровать   каждый   блок   средствами  AES  (SubBytes,  ShiftRows, 
MixColumns, AddRoundKey)
Дешифрование:
Подготовка раундовых ключей, но в обратном порядке
Разбить шифротекст на блоки по 16 байт
Дешифрование   каждого   блока   по  AES  (InvShiftRows,  InvSubBytes, 
AddRoundKey, InvMixColumns)
Удалить добавленные паддингом байты
Внимание! Допустимое использование библиотеки Crypto.Cipher.AES:
aes = AES.new(key, AES.MODE_ECB)

Алгоритм EAX
Шифрование:
Подготовить ключ AES, единый для шифрования и аутентификации
Сгенерировать Nonce уникальный и случайный выбранной длины
Определить дополнительный аутентификационные данные для аутентификации, 
которые не будут зашифрованы
Шифрование данных
oСгенерировать ключевой поток в режиме CTR
oВыполнить XOR ключевого потока с открытым текстом
oВычислить OMAC-тег для nonce, AEAD и шифротекста. Tag – OMAC(nonce || 
AAD || ciphertext, key)
Объединить nonce, шифротекст и AEAD
Дешифрование:
Подготовить ключ, тот же, что и при шифровании
Извлечь nonce, шифротекст и тег из данных
Проверка аутентификационного тега
oПовторить вычисление OMAC тега на основе nonce, AEAD и шифротекста
9
oПри несовпадении тега возвращать ошибку
Дешифрование данных
oВосстановить ключевой поток через AES-CTR
oВыполнить XOR ключевого потока с шифротекстом
При верном теге – вернуть данные, иначе вывести ошибку аутентификации
Внимание! Допустимое использование библиотеки Crypto.Cipher.AES:
aes = AES.new(key, AES.MODE_CTR)

Test vectors from here: https://www.cs.ucdavis.edu/~rogaway/papers/eax.pdf
"""
import os
from pathlib import Path
import typing as tp
import traceback

from Crypto.Cipher import AES
from Crypto.Hash import CMAC as OMAC

from Crypto.Random import get_random_bytes

from omac import omac

def get_omac_tag(nonce: bytes, aad: bytes, encrypted_message: bytes, key) -> bytes:
    tag_bytes = nonce + aad + encrypted_message

    cmac = OMAC.new(key, ciphermod=AES)
    tag_bytes_cmac = cmac.update(tag_bytes).digest()

    tag_bytes_omac = omac(key, tag_bytes)

    assert tag_bytes_cmac == tag_bytes_omac
    return tag_bytes_cmac

def encrypt(message: bytes, encryption_data: dict[str, tp.Any]) -> tp.Tuple[bytes, dict]:
    key = encryption_data['key']
    aad = encryption_data['aad']

    cipher = AES.new(key, AES.MODE_CTR)
    nonce = cipher.nonce
    encrypted_message = cipher.encrypt(message)
    omac_tag = get_omac_tag(nonce, aad, encrypted_message, key)

    return encrypted_message, {"nonce": nonce, "tag": omac_tag}

def decrypt(encrypted_message: bytes, decryption_data: dict[str, tp.Any]) -> bytes:
    key = decryption_data['key']
    nonce = decryption_data['nonce']
    awaited_tag = decryption_data['tag']
    aad = decryption_data['aad']
    reconstructed_tag = get_omac_tag(nonce, aad, encrypted_message, key)

    if awaited_tag != reconstructed_tag:
        raise ValueError(f"Tag mismatch: {awaited_tag} != {reconstructed_tag}")

    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    decrypted_message = cipher.decrypt(encrypted_message) # TODO: xor
    return decrypted_message

def get_encryption_data(log=False):
    encryption_data = {
        "key": get_random_bytes(192 // 8), # 24 bytes
        "aad": "userword:password".encode('utf-8'), # Additional Authentication Data
    }
    if log:
        print(encryption_data)
    return encryption_data

def test_text(text: str):
    encryption_data = get_encryption_data(log=True)
    encrypted, decryption_data =  encrypt(text.encode('utf-8'), encryption_data)
    # encrypted, _ =  encrypt((text+'kek').encode('utf-8'), encryption_data)
    decryption_data = {**decryption_data, "key": encryption_data["key"], "aad": encryption_data["aad"]}
    print(decryption_data)
    decrypted: bytes = decrypt(encrypted, decryption_data)
    decrypted_text: str = decrypted.decode('utf-8')

    assert text == decrypted_text, f'{text} != {decrypted_text}'


def cypher_file(path: str | Path, output_path: str | Path, overwrite: bool = True):
    path = Path(path)
    output_path = Path(output_path)
    if not path.exists():
        raise FileNotFoundError()
    if output_path.exists() and not overwrite:
        raise FileExistsError()
    elif output_path.exists():
        os.unlink(str(output_path))
    with open(path, 'rb') as f:
        content = f.read()

    encryption_data = get_encryption_data(log=True)
    encrypted_content, decryption_data = encrypt(content, encryption_data)
    with open(output_path, "wb") as f:
        f.write(encrypted_content)

    decryption_data.update(encryption_data)
    print(decryption_data)
    decrypted_content = decrypt(encrypted_content, decryption_data)

    assert decrypted_content == content

def main():
    # Some text tests
    try:
        test_text("1234567890_")
        test_text("1234567890_" * 10)
        test_text("1234567890_" * 7)
        print("✅ Text Checks passed")
    except AssertionError:
        print(f"❌ Text Checks failed \n{traceback.format_exc()}")

    # Encrypt/decrypt file
    try:
        cypher_file("infosec_labs/10/mit.txt", "infosec_labs/10/mit_encrypted.txt")
        print("✅ File Encryption Checks passed")
    except AssertionError:
        print(f"❌ File Encryption Checks failed \n{traceback.format_exc()}")

if __name__=='__main__':
    # AES-EAX 192 bit key
    main()