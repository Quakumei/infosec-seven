"""
    AES-EAX 192 bit key
    Внимание!
        Допустимое использование библиотеки Crypto.Cipher.AES:
            aes = AES.new(key, AES.MODE_CTR)
"""
import hmac

from Crypto.Cipher import AES

from logger import logger

def xor_with_keystream(plaintext: bytes, keystream: bytes) -> bytes:
    return bytes([pt ^ ks for pt, ks in zip(plaintext, keystream)])

def compute_omac(tag_data: bytes, key: bytes) -> bytes:
    h = hmac.HMAC(key, tag_data, 'sha256')
    return h.digest()

def encrypt(message: bytes, key: bytes, nonce: bytes, auth_data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CTR, nonce=b'', initial_value=nonce)
    ciphertext = cipher.encrypt(message)
    tag_data = nonce + auth_data + ciphertext
    tag = compute_omac(tag_data, key)

    return ciphertext + tag

def decrypt(data: bytes, key: bytes, nonce: bytes, auth_data: bytes, tag_length: int = 32) -> bytes:
    if len(data) <= tag_length:
        raise ValueError("Invalid encrypted data: too short to contain tag.")

    # Извлечение шифротекста и тега
    ciphertext = data[:-tag_length]
    received_tag = data[-tag_length:]

    # Повторное вычисление тега
    tag_data = nonce + auth_data + ciphertext
    expected_tag = compute_omac(tag_data, key)

    # Проверка подлинности
    logger.info(f"Received tag: {received_tag.hex()}")
    logger.info(f"Expected tag: {expected_tag.hex()}")
    if not hmac.compare_digest(received_tag, expected_tag):
        raise ValueError("Authentication failed: tag mismatch.")

    # Восстановление ключевого потока и расшифровка
    cipher = AES.new(key, AES.MODE_CTR, nonce=b'', initial_value=nonce)
    plaintext = cipher.decrypt(ciphertext)

    return plaintext
