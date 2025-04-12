import random
import os

pi0 = list(range(256)) # обеспечивет нелинейность, генерим числа от 0 до 255
random.shuffle(pi0)
pi1 = [pi0.index(i) for i in range(256)]

POLYNOMIAL = 0x1A9  # x⁸ + x⁷ + x⁵ + x³ + 1

def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

# поле Галуа GF(2⁸)
def gf_multiply(a, b):
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= POLYNOMIAL
        b >>= 1
    return result

# циклический сдвиг и XOR
def R(x):
    return ((x << 1) | (x >> 7)) & 0xFF

# линейное преобразование для диффузии
def L(x):
    for _ in range(16):
        x = R(x)
    return x

# обратное линейное преобразование
def L_inv(x):
    for _ in range(16):
        x = ((x >> 1) | (x << 7)) & 0xFF
    return x

# Разбиение ключа на два равных блока K1, K2
def split_key(key):
    return key[:16], key[16:]

# Генерация 10 раундовых ключей
def generate_round_keys(K1, K2):
    round_keys = [K1, K2]
    for i in range(8):
        K1 = bytes([L(b) for b in K1])
        K2 = bytes([L(b) for b in K2])
        round_keys.append(K1)
        round_keys.append(K2)
    return round_keys

# шифрование
def encrypt_block(block, round_keys):
    for i in range(9):
        block = xor_bytes(block, round_keys[i])
        block = bytes([pi0[b] for b in block]) # меняем каждый байтовы блок на соответсвующий из блока подстановки
        block = bytes([L(b) for b in block]) # проводим линейное преобразование
    block = xor_bytes(block, round_keys[9]) # с коненчным блоком просото выполняем xor
    return block

# дешифврование
def decrypt_block(block, round_keys):
    block = xor_bytes(block, round_keys[9])
    for i in range(8, -1, -1):
        block = bytes([L_inv(b) for b in block])
        block = bytes([pi1[b] for b in block])
        block = xor_bytes(block, round_keys[i])
    return block

# padding до размера кратного 16 байтам
def pad_data(data):
    padding_length = 16 - (len(data) % 16)
    return data + bytes([padding_length] * padding_length)

# удаление padding
def unpad_data(data):
    padding_length = data[-1]
    return data[:-padding_length]

def split_into_blocks(data):
    return [data[i:i+16] for i in range(0, len(data), 16)]

def encrypt(data, round_keys):
    data = pad_data(data)
    blocks = split_into_blocks(data)
    encrypted_blocks = [encrypt_block(block, round_keys) for block in blocks]
    return b''.join(encrypted_blocks)

def decrypt(data, round_keys):
    blocks = split_into_blocks(data)
    decrypted_blocks = [decrypt_block(block, round_keys) for block in blocks]
    return unpad_data(b''.join(decrypted_blocks))

def read_file(filename):
    with open(filename, 'rb') as f:
        return f.read()

def write_file(filename, data):
    with open(filename, 'wb') as f:
        f.write(data)

def main():
    key = os.urandom(32) #генерируем случайный ключ длинной 256 бит (то есть 32 байта)
    K1, K2 = split_key(key) # разбиваем ключ на два разных блока по 128 бит (16 байт)
    round_keys = generate_round_keys(K1, K2)

    # Чтение исходного сообщения
    plaintext = b"Karama Timur Ildarovich karama.ti@edu.spbstu.ru"
    with open('input', 'wb') as f:
        f.write(plaintext)
    #использует SP-сети S - substition P - permutation
    encrypted_data = encrypt(plaintext, round_keys)
    write_file('encrypted', encrypted_data)
    
    decrypted_data = decrypt(encrypted_data, round_keys)
    write_file('decrypted', decrypted_data)

    print("Исходный текст:", plaintext.decode('utf-8'))
    print("Зашифрованные данные:", encrypted_data)
    print("Расшифрованный текст:", decrypted_data.decode('utf-8'))

if __name__ == "__main__":
    main()
